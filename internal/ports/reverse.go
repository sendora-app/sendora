// SPDX-License-Identifier: AGPL-3.0-or-later

package ports

import (
	"context"
	"time"
)

// NewInvite is an upload invitation created by its owner. Reusable marks an
// open link that admits up to MaxUploads uploads (0 for a single-use invite).
type NewInvite struct {
	Token          string
	UserID         int64
	RecipientName  string
	RecipientEmail string
	Message        string
	ExpiresAt      time.Time
	Reusable       bool
	MaxUploads     int
}

// NewChildInvite is the single-use invite an open link creates for the guest
// that accepted it.
type NewChildInvite struct {
	Token         string
	UserID        int64
	RecipientName string
	Message       string
	GuestUserID   int64
	ExpiresAt     time.Time
	ParentID      int64
}

// InviteSummary is one of an owner's top-level invites (ListOwned). Used
// counts the completed child invites of an open link, Pending the open ones
// (not completed, expiring after the listing time).
type InviteSummary struct {
	ID             int64
	Token          string
	RecipientName  string
	RecipientEmail string
	ExpiresAt      time.Time
	CompletedAt    *time.Time
	Reusable       bool
	MaxUploads     int
	Used           int
	Pending        int
}

// InviteForAccept is what accepting an invitation needs. InviterName is the
// owner's display name, or the username when the name is empty.
type InviteForAccept struct {
	ID            int64
	GuestUserID   *int64
	ExpiresAt     time.Time
	CompletedAt   *time.Time
	RecipientName string
	Message       string
	InviterName   string
	Reusable      bool
	MaxUploads    int
	OwnerID       int64
	ParentID      *int64
}

// ReverseInviteRepository covers upload invitations (reverse_invites). Child
// invites (one per accepted open link) point at their open link as parent.
type ReverseInviteRepository interface {
	// CountOpenForGuest counts the invites of the guest account that are
	// not completed and expire after now.
	CountOpenForGuest(ctx context.Context, guestUserID int64, now time.Time) (int, error)

	// Create stores a top-level invite and returns its id. A token that is
	// already stored is an error.
	Create(ctx context.Context, in NewInvite) (int64, error)
	// ListOwned returns the owner's top-level invites, newest first (ties:
	// higher id first), with the child counts as of now. Unreadable rows are
	// skipped; an error while iterating ends the list without failing it.
	ListOwned(ctx context.Context, userID int64, now time.Time) ([]InviteSummary, error)
	// ExpireOwned lets the owner's top-level invite id expire at at and
	// returns the number of invites changed (0 when there is no such invite).
	ExpireOwned(ctx context.Context, id, userID int64, at time.Time) (int64, error)
	// ExpireOpenChildren lets the owner's child invites of parentID that are
	// not completed and still open at now expire at now.
	ExpireOpenChildren(ctx context.Context, parentID, userID int64, now time.Time) error

	// LockToken takes the write lock for the invite with token inside a
	// transaction (a no-op write; a missing token is not an error).
	LockToken(ctx context.Context, token string) error
	// ForAccept returns the invite with token whose owner is not a guest
	// (ErrNotFound otherwise).
	ForAccept(ctx context.Context, token string) (InviteForAccept, error)
	// CountTakenSlots counts the child invites of open link parentID that
	// hold an upload slot: completed ones, and those still open at now that
	// were created after recentSince (one-second precision) or have an upload
	// in progress.
	CountTakenSlots(ctx context.Context, parentID int64, now, recentSince time.Time) (int, error)
	// CreateChild stores a child invite for a guest.
	CreateChild(ctx context.Context, c NewChildInvite) error
	// AssignGuest records guestUserID as the guest account of invite id.
	AssignGuest(ctx context.Context, id, guestUserID int64) error

	// CountForGuest counts every invite of the guest account.
	CountForGuest(ctx context.Context, guestUserID int64) (int, error)
	// OpenForGuest returns the invite of the guest account that is not
	// completed, expires after now and belongs to a non-guest owner, with
	// that owner (ErrNotFound when there is none).
	OpenForGuest(ctx context.Context, guestUserID int64, now time.Time) (inviteID, ownerID int64, err error)
	// UploadSlot returns the parent open link of invite id (nil for a
	// top-level invite) and the uploads its parent admits (1 without a
	// parent); ErrNotFound for an unknown invite.
	UploadSlot(ctx context.Context, id int64) (parentID *int64, maxUploads int, err error)
	// CountUsedSiblings counts the child invites of parentID other than
	// exceptID that are completed or have an upload in progress.
	CountUsedSiblings(ctx context.Context, parentID, exceptID int64) (int, error)
	// CountValidForCompletion is 1 when invite id belongs to guestUserID and
	// ownerID, is not completed and expires after now, else 0.
	CountValidForCompletion(ctx context.Context, id, guestUserID, ownerID int64, now time.Time) (int, error)
	// Complete marks invite id completed (and used) at at while it is not
	// completed and expires after now; it returns the number of invites
	// changed.
	Complete(ctx context.Context, id int64, at, now time.Time) (int64, error)
}
