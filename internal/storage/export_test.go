// SPDX-License-Identifier: AGPL-3.0-or-later

package storage

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Test hooks for the emulator tests (package storage_test).

func S3PendingUploads(ctx context.Context, b Backend) (int, error) {
	sb := b.(*s3Backend)
	ups, err := sb.client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{Bucket: &sb.bucket})
	if err != nil {
		return 0, err
	}
	return len(ups.Uploads), nil
}
