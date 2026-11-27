// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import "context"

// NewUpload is an upload session to create. QuotaOwnerID is the account
// whose storage the session reserves (the inviter for a guest). InviteID is
// the guest's invite and ShareID the share the files are appended to; nil
// stores no value.
type NewUpload struct {
	ID           string
	UserID       int64
	InviteID     *int64
	QuotaOwnerID int64
	ShareID      *int64
}

// NewUploadFile is one declared file of an upload session.
type NewUploadFile struct {
	SessionID string
	Index     int
	Name      string
	FullPath  string
	Size      int64
	Type      string
	SHA256    string
}

// UploadFile is a declared file of an upload session with the bytes
// received so far.
type UploadFile struct {
	Index    int
	Name     string
	FullPath string
	Type     string
	Size     int64
	Received int64
	SHA256   string
}

// UploadProgress is the declared size and received bytes of one file.
type UploadProgress struct {
	Index    int
	Size     int64
	Received int64
}

// UploadRepository covers upload sessions and their declared files. A session
// reserves storage for its declared sizes until it is completed or deleted.
type UploadRepository interface {
	// CountAll counts every upload session.
	CountAll(ctx context.Context) (int64, error)
	// Create stores a new session. A taken id is an error.
	Create(ctx context.Context, u NewUpload) error
	// AddFile stores a declared file of a session. A taken (session, index)
	// is an error.
	AddFile(ctx context.Context, f NewUploadFile) error
	// Uploader returns the account that uploads into the session
	// (ErrNotFound for an unknown session).
	Uploader(ctx context.Context, id string) (int64, error)
	// CountByUploader counts the sessions of the uploading account.
	CountByUploader(ctx context.Context, userID int64) (int, error)
	// AppendTarget returns the share the session appends to (nil for a new
	// share; ErrNotFound for an unknown session).
	AppendTarget(ctx context.Context, id string) (*int64, error)
	// Reservation returns the quota owner and invite (nil when none) of the
	// session if userID uploads into it (ErrNotFound otherwise).
	Reservation(ctx context.Context, id string, userID int64) (quotaOwnerID int64, inviteID *int64, err error)

	// Progress returns the declared size and received bytes of the session's
	// files ordered by index. A row that cannot be read is listed with the
	// values read up to the failing column; an error while iterating ends
	// the list without failing it.
	Progress(ctx context.Context, id string) ([]UploadProgress, error)
	// Files returns the session's declared files ordered by index. An error
	// starting the read or a row that cannot be read is returned as is; an
	// error while iterating is returned wrapped in ErrReadInterrupted.
	Files(ctx context.Context, id string) ([]UploadFile, error)
	// FileState returns the declared size and received bytes of file idx
	// (ErrNotFound when the session has no such file).
	FileState(ctx context.Context, id string, idx int) (size, received int64, err error)
	// ReceivedOfUploader returns the received bytes of file idx if userID
	// uploads into the session (ErrNotFound otherwise).
	ReceivedOfUploader(ctx context.Context, id string, idx int, userID int64) (int64, error)
	// SetReceived records the received bytes of file idx.
	SetReceived(ctx context.Context, id string, idx int, received int64) error

	// LockForCompletion takes the write lock on the session inside a
	// transaction (a no-op write) while userID uploads into it, quotaOwnerID
	// still carries it, the uploader exists with the given guest flag and
	// the quota owner exists and is not a guest; it returns the number of
	// sessions matched (0 or 1).
	LockForCompletion(ctx context.Context, id string, userID, quotaOwnerID int64, uploaderIsGuest bool) (int64, error)
	// LockForAppend takes the write lock on the session inside a transaction
	// while userID uploads into it, quotaOwnerID carries it and it appends
	// to shareID; it returns the number of sessions matched (0 or 1).
	LockForAppend(ctx context.Context, id string, userID, quotaOwnerID, shareID int64) (int64, error)
	// Delete removes the session and its declared files; it returns the
	// number of sessions removed (a missing session is not an error).
	Delete(ctx context.Context, id string) (int64, error)
	// IDsForShare returns the ids of the sessions that append to the share,
	// in no particular order. Any read error fails the call.
	IDsForShare(ctx context.Context, shareID int64) ([]string, error)
	// IDsOfUploaderOrQuotaOwner returns the ids of the sessions the account
	// uploads into or carries, in no particular order. A row that cannot be
	// read fails the call.
	IDsOfUploaderOrQuotaOwner(ctx context.Context, userID int64) ([]string, error)
}
