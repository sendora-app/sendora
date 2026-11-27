// SPDX-License-Identifier: AGPL-3.0-or-later

package keyring

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/sendora-app/sendora/internal/colenc"
	"github.com/sendora-app/sendora/internal/filecrypt"
	"github.com/sendora-app/sendora/internal/ports"
)

// Codec is the ports.ColumnCodec of one tenant: it encrypts under the active
// key of the column's purpose ("data", or "audit-enc" for the audit log's
// text fields, see ColumnPurpose) and opens values of any version still in
// the keyring. Keys are
// loaded (and the control log verified) once per version and kept in memory;
// Close clears them.
type Codec struct {
	svc    *Service
	tenant string
	ctx    context.Context

	mu          sync.Mutex
	keys        map[pv]Key        // (purpose, version) -> unwrapped DEK
	subs        map[subKey][]byte // (purpose, version, table.column) -> subkey
	active      int               // active data version (Refresh follows rotations)
	auditActive int               // active audit-enc version
	index       Key               // active "index" key (blind indexes)

	filesActive int            // active "files" version (new files are written under it)
	fileMasters map[int][]byte // version -> file master key (filecrypt.MasterKey of the DEK)
	auditMAC    []byte         // subkey of "audit-mac" version 1 (the audit chain)
}

type subKey struct {
	purpose string
	version int
	use     string
}

// pv names one key version of one purpose.
type pv struct {
	purpose string
	version int
}

// ColumnPurpose is the key purpose that seals (table, column): the audit
// log's free-text fields use "audit-enc", every other encrypted column "data".
func ColumnPurpose(table, column string) string {
	if table == "audit_log" {
		return PurposeAuditEnc
	}
	return PurposeData
}

var _ ports.ColumnCodec = (*Codec)(nil)

// NewCodec verifies tenant's control log and loads the active data key.
func NewCodec(ctx context.Context, svc *Service, tenant string) (*Codec, error) {
	c := &Codec{svc: svc, tenant: tenant, ctx: ctx, keys: map[pv]Key{}, subs: map[subKey][]byte{}, fileMasters: map[int][]byte{}}
	k, err := svc.Load(ctx, tenant, PurposeData, 0)
	if err != nil {
		return nil, err
	}
	c.keys[pv{PurposeData, k.Version}] = k
	c.active = k.Version
	ak, err := svc.Load(ctx, tenant, PurposeAuditEnc, 0)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("the audit-enc key: %w", err)
	}
	c.keys[pv{PurposeAuditEnc, ak.Version}] = ak
	c.auditActive = ak.Version
	if c.index, err = svc.Load(ctx, tenant, PurposeIndex, 0); err != nil {
		clear(k.DEK)
		return nil, err
	}
	fv, err := c.loadFileMaster(0)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("the files key: %w", err)
	}
	c.filesActive = fv
	am, err := svc.Load(ctx, tenant, PurposeAuditMAC, 1)
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("the audit-mac key: %w", err)
	}
	c.auditMAC, err = Subkey(am, "chain")
	clear(am.DEK)
	if err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// ErrKeyRetired is returned for a file whose key version was retired.
var ErrKeyRetired = errors.New("keyring: the key version was retired")

// loadFileMaster loads the files key of version (0 = the active one) from the
// verified keyring into the cache and returns the version. A retired version
// is refused. The caller must not hold c.mu.
func (c *Codec) loadFileMaster(version int) (int, error) {
	st, err := c.svc.Verify(c.ctx, c.tenant)
	if err != nil {
		return 0, err
	}
	if version == 0 {
		version = st.Active[PurposeFiles]
	}
	switch st.States[PurposeFiles][version] {
	case StateActive, StateDecryptOnly:
	case StateRetired:
		return 0, fmt.Errorf("files key v%d: %w", version, ErrKeyRetired)
	default:
		return 0, fmt.Errorf("files key v%d does not exist", version)
	}
	k, err := c.svc.Load(c.ctx, c.tenant, PurposeFiles, version)
	if err != nil {
		return 0, err
	}
	m, err := filecrypt.MasterKey(k.DEK)
	clear(k.DEK)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.fileMasters[version]; ok {
		clear(m)
	} else if c.fileMasters == nil {
		clear(m)
		return 0, errors.New("the codec is closed")
	} else {
		c.fileMasters[version] = m
	}
	return version, nil
}

// FilesActive is the version of the files key new files are encrypted under.
func (c *Codec) FilesActive() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.filesActive
}

// FileMaster returns the file master key of version (the active one for 0),
// derived from that version of the tenant's files DEK. The slice is shared:
// callers must not modify it. A retired or unknown version is an error.
func (c *Codec) FileMaster(version int) ([]byte, int, error) {
	c.mu.Lock()
	if version == 0 {
		version = c.filesActive
	}
	m, ok := c.fileMasters[version]
	c.mu.Unlock()
	if ok {
		return m, version, nil
	}
	if _, err := c.loadFileMaster(version); err != nil {
		return nil, 0, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fileMasters[version], version, nil
}

// AuditMAC returns the HMAC-SHA256 function of the audit chain under the
// tenant's audit-mac key (version 1; the key cannot be rotated, see D45).
func (c *Codec) AuditMAC() func([]byte) []byte {
	key := append([]byte(nil), c.auditMAC...)
	return func(data []byte) []byte {
		m := hmac.New(sha256.New, key)
		m.Write(data)
		return m.Sum(nil)
	}
}

// Close clears every key held in memory.
func (c *Codec) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range c.keys {
		clear(k.DEK)
	}
	for _, s := range c.subs {
		clear(s)
	}
	clear(c.index.DEK)
	for _, m := range c.fileMasters {
		clear(m)
	}
	clear(c.auditMAC)
	c.keys, c.subs, c.fileMasters = map[pv]Key{}, map[subKey][]byte{}, nil
}

// sub returns the key of version and the subkey for use ("table.column").
func (c *Codec) sub(purpose string, version int, use string) (Key, []byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	k, ok := c.keys[pv{purpose, version}]
	if !ok {
		var err error
		if k, err = c.svc.Load(c.ctx, c.tenant, purpose, version); err != nil {
			return Key{}, nil, err
		}
		c.keys[pv{purpose, version}] = k
	}
	sk := subKey{purpose, version, use}
	if s, ok := c.subs[sk]; ok {
		return k, s, nil
	}
	s, err := Subkey(k, use)
	if err != nil {
		return Key{}, nil, err
	}
	c.subs[sk] = s
	return k, s, nil
}

func keyIDBytes(id string) ([16]byte, error) {
	u, err := uuid.Parse(id)
	return u, err
}

// Seal encrypts plaintext for (table, column, rowID) under the active key of
// the column's purpose.
func (c *Codec) Seal(table, column, rowID, plaintext string) (string, error) {
	purpose := ColumnPurpose(table, column)
	c.mu.Lock()
	version := c.active
	if purpose == PurposeAuditEnc {
		version = c.auditActive
	}
	c.mu.Unlock()
	k, sub, err := c.sub(purpose, version, table+"."+column)
	if err != nil {
		return "", err
	}
	id, err := keyIDBytes(k.KeyID)
	if err != nil {
		return "", err
	}
	ct, err := colenc.Encrypt(sub, id, uint32(k.Version), table, column, rowID, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return colenc.EncodeText(ct), nil
}

// Open decrypts a stored value; a value that is not an encrypted column value
// is ports.ErrNotEncrypted.
func (c *Codec) Open(table, column, rowID, stored string) (string, error) {
	ct, ok := colenc.DecodeText(stored)
	if !ok {
		return "", ports.ErrNotEncrypted
	}
	if len(ct) < colenc.MinCipherSize {
		return "", colenc.ErrInvalidCiphertext
	}
	version := int(binary.BigEndian.Uint32(ct[1:5]))
	purpose := ColumnPurpose(table, column)
	c.mu.Lock()
	newer := version > c.active
	if purpose == PurposeAuditEnc {
		newer = version > c.auditActive
	}
	c.mu.Unlock()
	if newer {
		// A value of a version this codec has not seen: another process
		// rotated. Follow it (best effort; the value opens without it).
		c.Refresh(c.ctx)
	}
	k, sub, err := c.sub(purpose, version, table+"."+column)
	if err != nil {
		return "", fmt.Errorf("column key v%d: %w", version, err)
	}
	id, err := keyIDBytes(k.KeyID)
	if err != nil {
		return "", err
	}
	pt, _, err := colenc.Decrypt(sub, id, table, column, rowID, ct)
	if err != nil {
		return "", errors.Join(errors.New("decrypting "+table+"."+column), err)
	}
	return string(pt), nil
}

// Versions returns the versions the codec encrypts with: the data key (Seal)
// and the index key (BlindIndex).
func (c *Codec) Versions() (data, index int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.active, c.index.Version
}

// Refresh re-reads the verified keyring and switches Seal and BlindIndex to
// the newest active data and index versions. A rotation done by another
// process (the controller, another replica) reaches this codec through it;
// values of any known version stay readable without it (Open loads a key the
// first time it meets its version). It reports whether a version changed.
func (c *Codec) Refresh(ctx context.Context) (bool, error) {
	st, err := c.svc.Verify(ctx, c.tenant)
	if err != nil {
		return false, err
	}
	c.mu.Lock()
	haveData, haveIndex := c.active, c.index.Version
	c.mu.Unlock()
	wantData, wantIndex := st.Active[PurposeData], st.Active[PurposeIndex]
	if wantData == 0 || wantIndex == 0 {
		return false, errors.New("keyring: no active data or index key")
	}
	changed := false
	if wantAudit := st.Active[PurposeAuditEnc]; wantAudit != 0 {
		c.mu.Lock()
		haveAudit := c.auditActive
		c.mu.Unlock()
		if wantAudit != haveAudit {
			if _, _, err := c.sub(PurposeAuditEnc, wantAudit, "refresh"); err != nil {
				return false, err
			}
			c.mu.Lock()
			if wantAudit > c.auditActive {
				c.auditActive = wantAudit
				changed = true
			}
			c.mu.Unlock()
		}
	}
	if wantFiles := st.Active[PurposeFiles]; wantFiles != 0 {
		c.mu.Lock()
		_, have := c.fileMasters[wantFiles]
		c.mu.Unlock()
		if !have {
			if _, err := c.loadFileMaster(wantFiles); err != nil {
				return false, err
			}
		}
		c.mu.Lock()
		if wantFiles > c.filesActive {
			c.filesActive = wantFiles
			changed = true
		}
		// A retired version is never used again: forget its key.
		for v, m := range c.fileMasters {
			if st.States[PurposeFiles][v] == StateRetired {
				clear(m)
				delete(c.fileMasters, v)
			}
		}
		c.mu.Unlock()
	}
	if wantData != haveData {
		if _, _, err := c.sub(PurposeData, wantData, "refresh"); err != nil {
			return false, err
		}
		c.mu.Lock()
		if wantData > c.active {
			c.active = wantData
			changed = true
		}
		c.mu.Unlock()
	}
	if wantIndex != haveIndex {
		k, err := c.svc.Load(ctx, c.tenant, PurposeIndex, wantIndex)
		if err != nil {
			return false, err
		}
		c.mu.Lock()
		if len(c.index.DEK) == 0 || k.Version <= c.index.Version { // closed, or raced with another refresh
			c.mu.Unlock()
			clear(k.DEK)
			return changed, nil
		}
		old := c.index
		c.index = k
		for sk, sub := range c.subs {
			if len(sk.use) > 6 && sk.use[:6] == "index:" {
				clear(sub)
				delete(c.subs, sk)
			}
		}
		c.mu.Unlock()
		clear(old.DEK)
		changed = true
	}
	return changed, nil
}

// indexView is a ColumnCodec that computes blind indexes under one given
// version of the index key (the staged version of a rotation) and delegates
// the rest to the codec.
type indexView struct {
	*Codec
	key Key
}

// BlindIndex implements ports.ColumnCodec under the view's key.
func (v indexView) BlindIndex(table, column, value string) ([]byte, error) {
	use := table + "." + column
	sub, err := Subkey(v.key, use)
	if err != nil {
		return nil, err
	}
	defer clear(sub)
	return colenc.BlindIndex(sub, use+"\x00", value), nil
}

// IndexView loads version of the index key (any version of the keyring,
// typically the staged one) and returns a codec that computes blind indexes
// with it. Call release when done: it clears the key.
func (c *Codec) IndexView(ctx context.Context, version int) (ports.ColumnCodec, func(), error) {
	k, err := c.svc.Load(ctx, c.tenant, PurposeIndex, version)
	if err != nil {
		return nil, nil, err
	}
	return indexView{Codec: c, key: k}, func() { clear(k.DEK) }, nil
}

// BlindIndex implements ports.ColumnCodec: the keyed, normalised, truncated
// HMAC of value for (table, column) under the active index key.
func (c *Codec) BlindIndex(table, column, value string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.index.DEK) == 0 {
		return nil, errors.New("blind index: the codec is closed")
	}
	use := table + "." + column
	sk := subKey{PurposeIndex, c.index.Version, "index:" + use}
	sub, ok := c.subs[sk]
	if !ok {
		var err error
		if sub, err = Subkey(c.index, use); err != nil {
			return nil, err
		}
		c.subs[sk] = sub
	}
	return colenc.BlindIndex(sub, use+"\x00", value), nil
}
