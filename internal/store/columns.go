// SPDX-License-Identifier: AGPL-3.0-or-later

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/sendora-app/sendora/internal/adapters/keysource"
	"github.com/sendora-app/sendora/internal/adapters/sqlite"
	"github.com/sendora-app/sendora/internal/keyring"
	"github.com/sendora-app/sendora/internal/ports"
)

// Column encryption of the SQLite flavours (docs/cluster/DESIGN.md 6.5, D39).
// Every encrypted database holds its own control log and keyring. The KEK that
// wraps its keys is derived from the key that opens the database file, so a
// tenant's database is keyed independently of every other tenant's, and the
// operator still has one secret to protect (the key file). The database's own
// log is bound to it through that key: a log copied into another database
// does not verify there.

const (
	columnKEKLabel = "sendora/v1/column-kek"
	columnLogID    = "local" // the control-log "tenant" of a database's own log
)

type remoteCfg struct {
	columns bool
	wrapKey []byte // wrapping key derived from a tenant-supplied KEK (D44)
}

// RemoteOpt configures OpenRemote.
type RemoteOpt func(*remoteCfg)

// WithTenantWrapKey gives the store the wrapping key derived from the tenant's
// own KEK (TenantWrapKey), so it can open the keyring of a tenant-managed
// tenant. The key is copied.
func WithTenantWrapKey(w []byte) RemoteOpt {
	return func(c *remoteCfg) { c.wrapKey = append([]byte(nil), w...) }
}

// WithColumnEncryption makes OpenRemote verify the database's control log and
// keys and encrypt the protected columns. The database must have been given
// its keys at provisioning (InitColumnKeys): the application role cannot write
// the control log, so a database without keys is refused (fail closed).
func WithColumnEncryption() RemoteOpt { return func(c *remoteCfg) { c.columns = true } }

// remoteKeyring is the keyring service of a remote database. Its KEK is
// derived from root, so every tenant database is keyed independently. This is
// the same model as the SQLite flavours; a controller-only KEK with an unwrap
// endpoint replaces it later (DESIGN 6.3).
func remoteKeyring(logs ports.ControlLogRepository, ring ports.KeyringRepository, root []byte) (*keyring.Service, error) {
	return remoteKeyringWith(logs, ring, root, nil)
}

// remoteKeyringWith is remoteKeyring that also holds the wrapping key of a
// tenant-supplied KEK (nil for none). With it the new wraps go under the
// tenant's KEK (it is the active one); the control log stays MACed under the
// platform's KEK, which both processes can always derive (D44).
func remoteKeyringWith(logs ports.ControlLogRepository, ring ports.KeyringRepository, root, wrap []byte) (*keyring.Service, error) {
	kek, err := DeriveKey(root, columnKEKLabel)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	ks, err := keysource.NewFromKey(kek)
	if err != nil {
		return nil, err
	}
	svc := &keyring.Service{KS: ks, Log: logs, Ring: ring, MACRef: keysource.Fingerprint(kek)}
	if len(wrap) == 32 {
		if err := ks.AddNamed(TenantWrapRef(wrap), wrap, true); err != nil {
			return nil, err
		}
	}
	return svc, nil
}

// InitColumnKeys creates the keys of a remote database when it has none (the
// controller does this while provisioning, as the database owner) and verifies
// them otherwise. It is idempotent so a resumed provisioning can repeat it.
func InitColumnKeys(ctx context.Context, logs ports.ControlLogRepository, ring ports.KeyringRepository, root []byte) error {
	svc, err := remoteKeyring(logs, ring, root)
	if err != nil {
		return err
	}
	switch _, verr := svc.Verify(ctx, columnLogID); {
	case verr == nil:
		return nil
	case errors.Is(verr, keyring.ErrNoLog):
		return svc.Init(ctx, columnLogID, "provision")
	default:
		return fmt.Errorf("the database's keys do not verify: %w", verr)
	}
}

// InitColumnCodec is InitColumnKeys that also returns the database's column
// codec, so what the provisioner seeds as the database owner (settings are
// encrypted columns) is sealed with the keys it just created. Close the codec
// (it has a Close method) when done.
func InitColumnCodec(ctx context.Context, logs ports.ControlLogRepository, ring ports.KeyringRepository, root []byte) (ports.ColumnCodec, error) {
	if err := InitColumnKeys(ctx, logs, ring, root); err != nil {
		return nil, err
	}
	svc, err := remoteKeyring(logs, ring, root)
	if err != nil {
		return nil, err
	}
	codec, err := keyring.NewCodec(ctx, svc, columnLogID)
	if err != nil {
		return nil, err
	}
	return codec, nil
}

func (s *Store) enableRemoteColumns(repos ports.Store, root, wrap []byte) error {
	sc, ok := repos.(interface{ SetCodec(ports.ColumnCodec) })
	if !ok {
		return errors.New("column encryption: the adapter has no codec support")
	}
	svc, err := remoteKeyringWith(repos.ControlLog(), repos.Keyring(), root, wrap)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if _, err := svc.Verify(ctx, columnLogID); err != nil {
		return fmt.Errorf("the database's keys do not verify (provisioned without keys?): %w", err)
	}
	codec, err := keyring.NewCodec(ctx, svc, columnLogID)
	if err != nil {
		return err
	}
	sc.SetCodec(codec)
	s.codec = codec
	return nil
}

// ErrLegacyColumns is returned when an encrypted database holds plaintext in
// columns that must be encrypted: it was created before column encryption
// (0.2.x). Run "sendora-db upgrade-encryption" on a backup-protected copy, or
// start a new database.
var ErrLegacyColumns = errors.New("the database holds plaintext in columns that must be encrypted (created before column encryption); run: sendora-db upgrade-encryption")

type openCfg struct{ upgradeColumns bool }

type openOpt func(*openCfg)

// withColumnUpgrade lets openStoreRoot encrypt plaintext columns of a database
// created before column encryption instead of refusing it.
func withColumnUpgrade() openOpt { return func(c *openCfg) { c.upgradeColumns = true } }

// enableColumnEncryption verifies (or, for a database without keys, creates)
// the database's keys, hands the codec to the repository layer and, when
// upgrade is set, encrypts plaintext values left by an older version.
func (s *Store) enableColumnEncryption(upgrade bool) error {
	kek, err := DeriveKey(s.cipherKey, columnKEKLabel)
	if err != nil {
		return err
	}
	defer clear(kek)
	ks, err := keysource.NewFromKey(kek)
	if err != nil {
		return err
	}
	a, ok := s.Repos().(*sqlite.Store)
	if !ok {
		return errors.New("column encryption needs the SQLite adapter")
	}
	ctx := context.Background()
	svc := &keyring.Service{KS: ks, Log: a.ControlLog(), Ring: a.Keyring()}
	plain, err := a.PlaintextColumns(ctx)
	if err != nil {
		return err
	}
	switch _, verr := svc.Verify(ctx, columnLogID); {
	case verr == nil:
	case errors.Is(verr, keyring.ErrNoLog):
		if plain > 0 && !upgrade {
			return fmt.Errorf("%w (%d values)", ErrLegacyColumns, plain)
		}
		if err := svc.Init(ctx, columnLogID, "start"); err != nil {
			return fmt.Errorf("creating the database's keys: %w", err)
		}
	default:
		return fmt.Errorf("the database's keys do not verify: %w", verr)
	}
	codec, err := keyring.NewCodec(ctx, svc, columnLogID)
	if err != nil {
		return err
	}
	if plain > 0 {
		if !upgrade {
			codec.Close()
			return fmt.Errorf("%w (%d values)", ErrLegacyColumns, plain)
		}
		n, err := a.EncryptPlaintextColumns(ctx, codec)
		if err != nil {
			codec.Close()
			return fmt.Errorf("encrypting the columns: %w", err)
		}
		s.columnsUpgraded = n
	}
	a.SetCodec(codec)
	s.codec = codec
	return nil
}

// UpgradeColumnEncryption opens the encrypted database in dataDir (key as for
// OpenEncrypted; root as for OpenTenant, nil for a native database), creates
// its keys if it has none, encrypts every plaintext value in the encrypted
// columns and returns how many it converted. Stop the application and take a
// backup first.
func UpgradeColumnEncryption(dataDir string, key, root []byte) (int, error) {
	if _, err := OpenEncryptedCheck(dataDir, key, false); err != nil {
		return 0, err
	}
	s, err := openStoreRoot(dataDir, key, root, withColumnUpgrade())
	if err != nil {
		return 0, err
	}
	defer s.Close()
	return s.columnsUpgraded, nil
}

// columnServiceFor is the keyring service of the database behind db, keyed
// from key (nil, nil when key is not 32 bytes).
func columnServiceFor(db *sql.DB, key []byte) (*keyring.Service, *sqlite.Store, error) {
	kek, err := DeriveKey(key, columnKEKLabel)
	if err != nil {
		return nil, nil, err
	}
	defer clear(kek)
	ks, err := keysource.NewFromKey(kek)
	if err != nil {
		return nil, nil, err
	}
	a := sqlite.New(db)
	return &keyring.Service{KS: ks, Log: a.ControlLog(), Ring: a.Keyring()}, a, nil
}

// columnCodecFor returns the codec of the database behind db, or nil when the
// database has no keys yet (values in its encrypted columns are plaintext).
func columnCodecFor(db *sql.DB, key []byte) (*keyring.Codec, error) {
	svc, _, err := columnServiceFor(db, key)
	if err != nil {
		return nil, err
	}
	c, err := keyring.NewCodec(context.Background(), svc, columnLogID)
	if errors.Is(err, keyring.ErrNoLog) {
		return nil, nil
	}
	return c, err
}

// resealExport re-keys the column layer of destination, a sqlcipher_export copy
// of source made under another key: the encrypted values are opened with
// source's keys, the copied (now unverifiable) keys are dropped, new keys are
// created from destinationKey and the values are sealed with them.
func resealExport(source, destination string, sourceKey, destinationKey []byte) error {
	srcDB, err := openCipherDB(source, sourceKey, true)
	if err != nil {
		return err
	}
	defer srcDB.Close()
	from, err := columnCodecFor(srcDB, sourceKey)
	if err != nil {
		return fmt.Errorf("the source's keys do not verify: %w", err)
	}
	// The keys that protect what lives outside the data columns (stored files,
	// the audit chain's MAC) and the audit log's text fields (audit-enc, whose
	// rows are only ever re-sealed in the copy, never rewritten in a live log)
	// move to the copy's new keyring unchanged; the data keys are new.
	var carried []keyring.Carried
	if from != nil {
		defer from.Close()
		srcSvc, _, err := columnServiceFor(srcDB, sourceKey)
		if err != nil {
			return err
		}
		if carried, err = srcSvc.Export(context.Background(), columnLogID, keyring.PurposeFiles, keyring.PurposeAuditMAC, keyring.PurposeAuditEnc); err != nil {
			return fmt.Errorf("reading the source's files and audit keys: %w", err)
		}
		defer func() {
			for _, c := range carried {
				clear(c.DEK)
			}
		}()
	}
	dstDB, err := openCipherDB(destination, destinationKey, false)
	if err != nil {
		return err
	}
	defer dstDB.Close()
	svc, a, err := columnServiceFor(dstDB, destinationKey)
	if err != nil {
		return err
	}
	ctx := context.Background()
	if err := a.DropKeys(ctx); err != nil {
		return err
	}
	if err := svc.InitCarrying(ctx, columnLogID, "reseal", carried); err != nil {
		return fmt.Errorf("creating the copy's keys: %w", err)
	}
	to, err := keyring.NewCodec(ctx, svc, columnLogID)
	if err != nil {
		return err
	}
	defer to.Close()
	var fromCodec ports.ColumnCodec
	if from != nil {
		fromCodec = from
	}
	_, err = a.ResealColumns(ctx, fromCodec, to)
	return err
}

// ColumnKeyID is the control-log identity of a database's own keys (the
// "tenant" argument of keyring.Service and keyring.NewCodec).
const ColumnKeyID = columnLogID

// ColumnKeyring returns the codec of an encrypted database (nil when the
// database does not encrypt its columns).
func (s *Store) ColumnKeyring() *keyring.Codec { return s.codec }

// KeyringService returns the keyring service of the database's own keys. On a
// SQLite database it can write the control log; on a remote (PostgreSQL)
// database the application role cannot, so there it only reads and verifies:
// the controller writes with RemoteKeyring on the owner connection.
func (s *Store) KeyringService() (*keyring.Service, error) {
	if s.codec == nil {
		return nil, errors.New("column encryption is not enabled")
	}
	if s.Remote() {
		return remoteKeyringWith(s.Repos().ControlLog(), s.Repos().Keyring(), s.rootKey, s.tenantWrap)
	}
	svc, _, err := columnServiceFor(s.DB, s.cipherKey)
	return svc, err
}

// RemoteKeyring is the keyring service of a remote tenant database reached
// through logs and ring (the controller passes owner-role repositories) with
// the tenant's key root.
func RemoteKeyring(logs ports.ControlLogRepository, ring ports.KeyringRepository, root []byte) (*keyring.Service, error) {
	return remoteKeyring(logs, ring, root)
}

// RemoteKeyringWithTenantKEK is RemoteKeyring for a tenant that may hold its
// own KEK: wrap is the wrapping key derived from it (TenantWrapKey), nil when
// the tenant is platform-managed or locked.
func RemoteKeyringWithTenantKEK(logs ports.ControlLogRepository, ring ports.KeyringRepository, root, wrap []byte) (*keyring.Service, error) {
	return remoteKeyringWith(logs, ring, root, wrap)
}
