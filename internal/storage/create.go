// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// CreateBucket creates the bucket or container of b when it does not exist.
// Sendora itself never creates buckets (they are provisioned with their
// access policy by the operator); this is for emulators in tests and tools.
func CreateBucket(ctx context.Context, b Backend) error {
	switch be := b.(type) {
	case *s3Backend:
		_, err := be.client.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &be.bucket})
		if err != nil && (strings.Contains(err.Error(), "BucketAlreadyOwnedByYou") || strings.Contains(err.Error(), "BucketAlreadyExists")) {
			return nil
		}
		return err
	case *azureBackend:
		_, err := be.container.Create(ctx, nil)
		if err != nil && bloberror.HasCode(err, bloberror.ContainerAlreadyExists) {
			return nil
		}
		return err
	case *gcsBackend:
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, be.endpoint+"/storage/v1/b?project=sendora", strings.NewReader(`{"name":"`+url.PathEscape(be.bucket)+`"}`))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		res, err := be.client.Do(req)
		if err != nil {
			return err
		}
		return gcsCheck(res, http.StatusOK, http.StatusConflict)
	case *Local:
		return nil
	}
	return errors.New("storage: cannot create buckets for this backend")
}
