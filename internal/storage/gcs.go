// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// The GCS backend talks to the Cloud Storage JSON API over plain HTTPS with
// golang.org/x/oauth2/google for credentials, instead of the official client
// library: that library pulls in gRPC, protobuf and OpenTelemetry (well over
// 10 MB of binary) for the five calls Sendora needs.
const gcsScope = "https://www.googleapis.com/auth/devstorage.read_write"

type gcsBackend struct {
	client   *http.Client
	endpoint string
	bucket   string
	prefix   string
}

func newGCS(ctx context.Context, c Config) (*gcsBackend, error) {
	base := &http.Client{Transport: httpTransport(c)}
	client := base
	switch c.GCSAuth {
	case GCSAuthServiceAcct:
		// The token requests (token_uri of the key) go through base as well,
		// so a tenant's key cannot point them at an internal address.
		tokenCtx := context.WithValue(ctx, oauth2.HTTPClient, base)
		creds, err := google.CredentialsFromJSONWithType(tokenCtx, []byte(c.GCSCredentialsJSON), google.ServiceAccount, gcsScope)
		if err != nil {
			return nil, errors.New("invalid GCS service account JSON key")
		}
		client = oauth2.NewClient(context.WithValue(context.Background(), oauth2.HTTPClient, base), creds.TokenSource)
	case GCSAuthDefault:
		// Application Default Credentials: GKE workload identity / the metadata
		// server, GOOGLE_APPLICATION_CREDENTIALS, or gcloud's user credentials.
		creds, err := google.FindDefaultCredentials(ctx, gcsScope)
		if err != nil {
			return nil, fmt.Errorf("GCS default credentials: %w", err)
		}
		client = oauth2.NewClient(context.WithValue(context.Background(), oauth2.HTTPClient, base), creds.TokenSource)
	}
	return &gcsBackend{client: client, endpoint: c.gcsEndpoint(), bucket: c.GCSBucket, prefix: c.Prefix}, nil
}

func (b *gcsBackend) Kind() string { return KindGCS }

func (b *gcsBackend) full(key string) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	return b.prefix + key, nil
}

func (b *gcsBackend) objectURL(full string) string {
	return b.endpoint + "/storage/v1/b/" + url.PathEscape(b.bucket) + "/o/" + url.PathEscape(full)
}

type gcsError struct {
	status int
	msg    string
}

func (e *gcsError) Error() string { return fmt.Sprintf("GCS: HTTP %d: %s", e.status, e.msg) }

func gcsCheck(res *http.Response, ok ...int) error {
	for _, c := range ok {
		if res.StatusCode == c {
			return nil
		}
	}
	body, _ := io.ReadAll(io.LimitReader(res.Body, 2048))
	res.Body.Close()
	var parsed struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &parsed) == nil && parsed.Error.Message != "" {
		msg = parsed.Error.Message
	}
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if res.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%w: %s", ErrNotExist, msg)
	}
	return &gcsError{res.StatusCode, msg}
}

// Put is a single media upload with a known length: the object exists only
// once the request completed, so a failure leaves nothing behind.
func (b *gcsBackend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	full, err := b.full(key)
	if err != nil {
		return err
	}
	u := b.endpoint + "/upload/storage/v1/b/" + url.PathEscape(b.bucket) + "/o?uploadType=media&name=" + url.QueryEscape(full)
	src := &exactReader{r: r, left: size}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, io.NopCloser(src))
	if err != nil {
		return err
	}
	req.ContentLength = size
	if size == 0 {
		req.Body = http.NoBody
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	res, err := b.client.Do(req)
	if err != nil {
		if src.left == 0 {
			// Every byte was sent before the failure (for example a source
			// longer than announced): the service may have stored the object.
			b.Delete(context.WithoutCancel(ctx), key)
		}
		return err
	}
	if err := gcsCheck(res, http.StatusOK); err != nil {
		return err
	}
	res.Body.Close()
	// The request sends exactly size bytes; a longer source is an error too.
	if err := src.drain(); err != nil {
		b.Delete(context.WithoutCancel(ctx), key)
		return err
	}
	return nil
}

type gcsMeta struct {
	Name    string    `json:"name"`
	Size    string    `json:"size"`
	Updated time.Time `json:"updated"`
}

func (m gcsMeta) info(prefix string) Info {
	n, _ := strconv.ParseInt(m.Size, 10, 64)
	return Info{Key: strings.TrimPrefix(m.Name, prefix), Size: n, ModTime: m.Updated}
}

func (b *gcsBackend) get(ctx context.Context, u string, header http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range header {
		req.Header[k] = v
	}
	return b.client.Do(req)
}

func (b *gcsBackend) Stat(ctx context.Context, key string) (Info, error) {
	full, err := b.full(key)
	if err != nil {
		return Info{}, err
	}
	res, err := b.get(ctx, b.objectURL(full), nil)
	if err != nil {
		return Info{}, err
	}
	if err := gcsCheck(res, http.StatusOK); err != nil {
		if errors.Is(err, ErrNotExist) {
			return Info{}, ErrNotExist
		}
		return Info{}, err
	}
	defer res.Body.Close()
	var m gcsMeta
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&m); err != nil {
		return Info{}, err
	}
	return m.info(b.prefix), nil
}

func (b *gcsBackend) Open(ctx context.Context, key string) (Object, error) {
	info, err := b.Stat(ctx, key)
	if err != nil {
		return nil, err
	}
	full, _ := b.full(key)
	return newRemoteObject(ctx, info.Size, info.ModTime, func(ctx context.Context, off int64) (io.ReadCloser, error) {
		res, err := b.get(ctx, b.objectURL(full)+"?alt=media", http.Header{"Range": {"bytes=" + strconv.FormatInt(off, 10) + "-"}})
		if err != nil {
			return nil, err
		}
		if err := gcsCheck(res, http.StatusOK, http.StatusPartialContent); err != nil {
			return nil, err
		}
		if res.StatusCode == http.StatusOK && off > 0 {
			// The server ignored the range: skip to the offset.
			if _, err := io.CopyN(io.Discard, res.Body, off); err != nil {
				res.Body.Close()
				return nil, err
			}
		}
		return res.Body, nil
	}), nil
}

func (b *gcsBackend) Delete(ctx context.Context, key string) error {
	full, err := b.full(key)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, b.objectURL(full), nil)
	if err != nil {
		return err
	}
	res, err := b.client.Do(req)
	if err != nil {
		return err
	}
	if err := gcsCheck(res, http.StatusNoContent, http.StatusOK); err != nil {
		if errors.Is(err, ErrNotExist) {
			return nil
		}
		return err
	}
	res.Body.Close()
	return nil
}

func (b *gcsBackend) List(ctx context.Context, prefix string, fn func(Info) error) error {
	token := ""
	for {
		q := url.Values{"prefix": {b.prefix + prefix}, "fields": {"items(name,size,updated),nextPageToken"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		res, err := b.get(ctx, b.endpoint+"/storage/v1/b/"+url.PathEscape(b.bucket)+"/o?"+q.Encode(), nil)
		if err != nil {
			return err
		}
		if err := gcsCheck(res, http.StatusOK); err != nil {
			return err
		}
		var page struct {
			Items         []gcsMeta `json:"items"`
			NextPageToken string    `json:"nextPageToken"`
		}
		err = json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(&page)
		res.Body.Close()
		if err != nil {
			return err
		}
		for _, m := range page.Items {
			if err := fn(m.info(b.prefix)); err != nil {
				return err
			}
		}
		if page.NextPageToken == "" {
			return nil
		}
		token = page.NextPageToken
	}
}
