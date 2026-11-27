// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// s3MinPart is the smallest multipart part (S3 requires 5 MiB except for the
// last part); parts are buffered in memory so every request has a known,
// seekable body (needed for SigV4 over plain http to MinIO and for retries).
const (
	s3MinPart  = 8 << 20
	s3MaxParts = 10000
)

type s3Backend struct {
	client *s3.Client
	bucket string
	prefix string
}

func newS3(ctx context.Context, c Config) (*s3Backend, error) {
	var cfg aws.Config
	if c.S3Auth == S3AuthDefault {
		// The default chain: environment, shared config, web identity (IRSA,
		// EKS Pod Identity), ECS task role and the EC2 instance profile.
		var err error
		cfg, err = awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(c.S3Region))
		if err != nil {
			return nil, fmt.Errorf("S3 default credentials: %w", err)
		}
	} else {
		cfg = aws.Config{
			Region:      c.S3Region,
			Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(c.S3AccessKey, c.S3SecretKey, "")),
		}
	}
	cfg.HTTPClient = &http.Client{Timeout: 0, Transport: httpTransport(c)}
	cfg.RetryMaxAttempts = 4
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = c.S3PathStyle
		if c.S3Endpoint != "" {
			o.BaseEndpoint = aws.String(c.S3Endpoint)
		}
		// Not every S3-compatible service (B2, older MinIO, R2) accepts the
		// newer default CRC checksums; integrity is ensured by GCM anyway.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})
	return &s3Backend{client: client, bucket: c.S3Bucket, prefix: c.Prefix}, nil
}

func (b *s3Backend) Kind() string { return KindS3 }

func (b *s3Backend) full(key string) (string, error) {
	if err := validKey(key); err != nil {
		return "", err
	}
	return b.prefix + key, nil
}

func s3PartSize(size int64) int64 {
	part := int64(s3MinPart)
	for size/part >= s3MaxParts {
		part *= 2
	}
	return part
}

func (b *s3Backend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	full, err := b.full(key)
	if err != nil {
		return err
	}
	src := &exactReader{r: r, left: size}
	part := s3PartSize(size)
	if size <= part {
		buf := make([]byte, size)
		if _, err := io.ReadFull(src, buf); err != nil {
			return err
		}
		if err := src.drain(); err != nil {
			return err
		}
		_, err := b.client.PutObject(ctx, &s3.PutObjectInput{Bucket: &b.bucket, Key: &full, Body: bytes.NewReader(buf), ContentLength: aws.Int64(size),
			ContentType: aws.String("application/octet-stream")})
		return err
	}
	up, err := b.client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{Bucket: &b.bucket, Key: &full, ContentType: aws.String("application/octet-stream")})
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			// Never leave stored parts behind (they would be billed and invisible).
			b.client.AbortMultipartUpload(context.WithoutCancel(ctx), &s3.AbortMultipartUploadInput{Bucket: &b.bucket, Key: &full, UploadId: up.UploadId})
		}
	}()
	buf := make([]byte, part)
	var parts []s3types.CompletedPart
	for n := int32(1); ; n++ {
		got, err := readPart(src, buf)
		if err != nil {
			return err
		}
		if got == 0 {
			break
		}
		res, err := b.client.UploadPart(ctx, &s3.UploadPartInput{Bucket: &b.bucket, Key: &full, UploadId: up.UploadId, PartNumber: aws.Int32(n),
			Body: bytes.NewReader(buf[:got]), ContentLength: aws.Int64(int64(got))})
		if err != nil {
			return err
		}
		parts = append(parts, s3types.CompletedPart{ETag: res.ETag, PartNumber: aws.Int32(n)})
		if got < len(buf) {
			break
		}
	}
	if err := src.drain(); err != nil {
		return err
	}
	if _, err := b.client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{Bucket: &b.bucket, Key: &full, UploadId: up.UploadId,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: parts}}); err != nil {
		return err
	}
	ok = true
	return nil
}

func s3NotFound(err error) bool {
	var nsk *s3types.NoSuchKey
	var nf *s3types.NotFound
	if errors.As(err, &nsk) || errors.As(err, &nf) {
		return true
	}
	var ae smithy.APIError
	return errors.As(err, &ae) && (ae.ErrorCode() == "NotFound" || ae.ErrorCode() == "NoSuchKey")
}

func (b *s3Backend) Stat(ctx context.Context, key string) (Info, error) {
	full, err := b.full(key)
	if err != nil {
		return Info{}, err
	}
	h, err := b.client.HeadObject(ctx, &s3.HeadObjectInput{Bucket: &b.bucket, Key: &full})
	if err != nil {
		if s3NotFound(err) {
			return Info{}, ErrNotExist
		}
		return Info{}, err
	}
	info := Info{Key: key, Size: aws.ToInt64(h.ContentLength)}
	if h.LastModified != nil {
		info.ModTime = *h.LastModified
	}
	return info, nil
}

func (b *s3Backend) Open(ctx context.Context, key string) (Object, error) {
	info, err := b.Stat(ctx, key)
	if err != nil {
		return nil, err
	}
	full, _ := b.full(key)
	return newRemoteObject(ctx, info.Size, info.ModTime, func(ctx context.Context, off int64) (io.ReadCloser, error) {
		out, err := b.client.GetObject(ctx, &s3.GetObjectInput{Bucket: &b.bucket, Key: &full, Range: aws.String("bytes=" + strconv.FormatInt(off, 10) + "-")})
		if err != nil {
			if s3NotFound(err) {
				return nil, ErrNotExist
			}
			return nil, err
		}
		return out.Body, nil
	}), nil
}

func (b *s3Backend) Delete(ctx context.Context, key string) error {
	full, err := b.full(key)
	if err != nil {
		return err
	}
	_, err = b.client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &b.bucket, Key: &full})
	if err != nil && s3NotFound(err) {
		return nil
	}
	return err
}

func (b *s3Backend) List(ctx context.Context, prefix string, fn func(Info) error) error {
	full := b.prefix + prefix
	p := s3.NewListObjectsV2Paginator(b.client, &s3.ListObjectsV2Input{Bucket: &b.bucket, Prefix: &full})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, o := range page.Contents {
			info := Info{Key: aws.ToString(o.Key)[len(b.prefix):], Size: aws.ToInt64(o.Size)}
			if o.LastModified != nil {
				info.ModTime = *o.LastModified
			}
			if err := fn(info); err != nil {
				return err
			}
		}
	}
	return nil
}

// httpTransport is the shared transport of the remote backends: bounded
// connection setup and header waits, while bodies may stream for long.
// A configuration with DialContext (a tenant's own storage in multi-tenant
// mode, see internal/netguard) connects only through it and never through a
// proxy, so the guard sees the real destination.
func httpTransport(c Config) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = 60 * time.Second
	t.MaxIdleConnsPerHost = 16
	if c.DialContext != nil {
		t.DialContext = c.DialContext
		t.Proxy = nil
	}
	return t
}
