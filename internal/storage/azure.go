// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
)

type azureBackend struct {
	container *container.Client
	prefix    string
}

func newAzure(c Config) (*azureBackend, error) {
	opts := &azblob.ClientOptions{ClientOptions: azcore.ClientOptions{
		Transport: &http.Client{Transport: httpTransport(c)},
		Retry:     policy.RetryOptions{MaxRetries: 4},
	}}
	serviceURL := c.azureServiceURL()
	var (
		client *azblob.Client
		err    error
	)
	switch c.AzureAuth {
	case AzureAuthSharedKey:
		cred, cerr := azblob.NewSharedKeyCredential(c.AzureAccount, c.AzureAccountKey)
		if cerr != nil {
			return nil, errors.New("invalid Azure account key")
		}
		client, err = azblob.NewClientWithSharedKeyCredential(serviceURL, cred, opts)
	case AzureAuthSAS:
		client, err = azblob.NewClientWithNoCredential(strings.TrimRight(serviceURL, "/")+"/?"+strings.TrimPrefix(c.AzureSASToken, "?"), opts)
	default:
		// Workload identity (AKS), managed identity, environment variables or
		// the Azure CLI, in the order DefaultAzureCredential tries them.
		cred, cerr := azidentity.NewDefaultAzureCredential(nil)
		if cerr != nil {
			return nil, cerr
		}
		client, err = azblob.NewClient(serviceURL, cred, opts)
	}
	if err != nil {
		return nil, err
	}
	return &azureBackend{container: client.ServiceClient().NewContainerClient(c.AzureContainer), prefix: c.Prefix}, nil
}

func (b *azureBackend) Kind() string { return KindAzure }

func (b *azureBackend) blob(key string) (*blockblob.Client, error) {
	if err := validKey(key); err != nil {
		return nil, err
	}
	return b.container.NewBlockBlobClient(b.prefix + key), nil
}

// Put stages blocks and commits the block list only when every byte arrived;
// uncommitted blocks of a failed upload are discarded by the service.
func (b *azureBackend) Put(ctx context.Context, key string, r io.Reader, size int64) error {
	bb, err := b.blob(key)
	if err != nil {
		return err
	}
	src := &exactReader{r: r, left: size}
	_, err = bb.UploadStream(ctx, src, &blockblob.UploadStreamOptions{BlockSize: 8 << 20, Concurrency: 2,
		HTTPHeaders: &blob.HTTPHeaders{BlobContentType: strPtr("application/octet-stream")}})
	return err
}

func strPtr(s string) *string { return &s }

func azureNotFound(err error) bool {
	return bloberror.HasCode(err, bloberror.BlobNotFound, bloberror.ResourceNotFound)
}

func (b *azureBackend) Stat(ctx context.Context, key string) (Info, error) {
	bb, err := b.blob(key)
	if err != nil {
		return Info{}, err
	}
	p, err := bb.GetProperties(ctx, nil)
	if err != nil {
		var re *azcore.ResponseError
		if azureNotFound(err) || (errors.As(err, &re) && re.StatusCode == http.StatusNotFound) {
			return Info{}, ErrNotExist
		}
		return Info{}, err
	}
	info := Info{Key: key}
	if p.ContentLength != nil {
		info.Size = *p.ContentLength
	}
	if p.LastModified != nil {
		info.ModTime = *p.LastModified
	}
	return info, nil
}

func (b *azureBackend) Open(ctx context.Context, key string) (Object, error) {
	info, err := b.Stat(ctx, key)
	if err != nil {
		return nil, err
	}
	bb, _ := b.blob(key)
	return newRemoteObject(ctx, info.Size, info.ModTime, func(ctx context.Context, off int64) (io.ReadCloser, error) {
		res, err := bb.DownloadStream(ctx, &blob.DownloadStreamOptions{Range: blob.HTTPRange{Offset: off}})
		if err != nil {
			if azureNotFound(err) {
				return nil, ErrNotExist
			}
			return nil, err
		}
		return res.Body, nil
	}), nil
}

func (b *azureBackend) Delete(ctx context.Context, key string) error {
	bb, err := b.blob(key)
	if err != nil {
		return err
	}
	_, err = bb.Delete(ctx, nil)
	if err != nil && azureNotFound(err) {
		return nil
	}
	return err
}

func (b *azureBackend) List(ctx context.Context, prefix string, fn func(Info) error) error {
	full := b.prefix + prefix
	pager := b.container.NewListBlobsFlatPager(&container.ListBlobsFlatOptions{Prefix: &full})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, item := range page.Segment.BlobItems {
			if item.Name == nil {
				continue
			}
			info := Info{Key: (*item.Name)[len(b.prefix):]}
			if item.Properties != nil {
				if item.Properties.ContentLength != nil {
					info.Size = *item.Properties.ContentLength
				}
				if item.Properties.LastModified != nil {
					info.ModTime = *item.Properties.LastModified
				}
			}
			if err := fn(info); err != nil {
				return err
			}
		}
	}
	return nil
}
