// SPDX-License-Identifier: AGPL-3.0-or-later

package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

// MigrateStorage creates the storage tables, the location columns of files
// and the trigger that queues a removed file's remote object.
func MigrateStorage(db *sql.DB) error {
	if _, err := db.Exec(`
CREATE TABLE IF NOT EXISTS storage_locations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  backend TEXT NOT NULL,
  identity TEXT NOT NULL UNIQUE,
  config TEXT NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS storage_pending_deletes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  location_id INTEGER NOT NULL,
  object_key TEXT NOT NULL,
  not_before DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS storage_migrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  status TEXT NOT NULL DEFAULT 'running',
  target_location INTEGER NOT NULL,
  target TEXT NOT NULL DEFAULT '',
  total INTEGER NOT NULL DEFAULT 0,
  done INTEGER NOT NULL DEFAULT 0,
  failed INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0,
  started_by TEXT NOT NULL DEFAULT '',
  started_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at DATETIME,
  error TEXT NOT NULL DEFAULT ''
);`); err != nil {
		return err
	}
	for _, c := range []struct{ table, name, decl string }{
		{"files", "storage_id", "INTEGER NOT NULL DEFAULT 0"},
		{"files", "object_key", "TEXT NOT NULL DEFAULT ''"},
	} {
		if err := addColumnIfMissing(db, c.table, c.name, c.decl); err != nil {
			return err
		}
	}
	// Deleting a files row (one file, a share, a user, an erasure: also through
	// ON DELETE CASCADE) queues its remote object for deletion in the same
	// transaction, so no code path can forget a remote object. Local files keep
	// their directory-based removal.
	_, err := db.Exec(`CREATE TRIGGER IF NOT EXISTS files_remote_deleted AFTER DELETE ON files
WHEN OLD.storage_id<>0 AND OLD.object_key<>''
BEGIN INSERT INTO storage_pending_deletes(location_id,object_key) VALUES(OLD.storage_id,OLD.object_key); END;`)
	return err
}

func addColumnIfMissing(db *sql.DB, table, name, decl string) error {
	found, err := hasColumn(db, table, name)
	if err != nil || found {
		return err
	}
	_, err = db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, name, decl))
	return err
}

type objectStorageRepo struct {
	q     querier
	codec ports.ColumnCodec
}

func (r objectStorageRepo) EnsureLocation(ctx context.Context, backend, identity, config string) (int64, error) {
	if r.codec != nil {
		return r.ensureSealed(ctx, backend, identity, config)
	}
	var id int64
	err := r.q.QueryRowContext(ctx, `INSERT INTO storage_locations(backend,identity,config) VALUES(?,?,?)
		ON CONFLICT(identity) DO UPDATE SET config=excluded.config, updated_at=CASE WHEN config<>excluded.config THEN CURRENT_TIMESTAMP ELSE updated_at END
		RETURNING id`, backend, identity, config).Scan(&id)
	return id, err
}

func (r objectStorageRepo) LocationConfig(ctx context.Context, id int64) (string, error) {
	var js string
	err := r.q.QueryRowContext(ctx, `SELECT config FROM storage_locations WHERE id=?`, id).Scan(&js)
	if err != nil {
		return js, notFound(err)
	}
	return openCol(r.codec, "storage_locations", "config", id, js)
}

func (r objectStorageRepo) LocationConfigs(ctx context.Context) ([]string, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id, config FROM storage_locations ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id int64
		var js string
		if rows.Scan(&id, &js) != nil {
			continue
		}
		js, err := openCol(r.codec, "storage_locations", "config", id, js)
		if err != nil {
			return nil, err
		}
		out = append(out, js)
	}
	return out, rows.Err()
}

func (r objectStorageRepo) QueueDelete(ctx context.Context, location int64, key string, notBefore time.Time) error {
	_, err := r.q.ExecContext(ctx, `INSERT INTO storage_pending_deletes(location_id,object_key,not_before) VALUES(?,?,?)`, location, key, notBefore)
	return err
}

func (r objectStorageRepo) CountPendingDeletes(ctx context.Context) (int64, error) {
	var n int64
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM storage_pending_deletes`).Scan(&n)
	return n, err
}

func (r objectStorageRepo) DuePendingDeletes(ctx context.Context, now time.Time, limit int) ([]ports.PendingDelete, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id,location_id,object_key,attempts FROM storage_pending_deletes WHERE not_before<=? ORDER BY id LIMIT ?`, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.PendingDelete
	for rows.Next() {
		var j ports.PendingDelete
		if rows.Scan(&j.ID, &j.LocationID, &j.ObjectKey, &j.Attempts) == nil {
			out = append(out, j)
		}
	}
	return out, nil
}

func (r objectStorageRepo) DeletePendingDelete(ctx context.Context, id int64) error {
	_, err := r.q.ExecContext(ctx, `DELETE FROM storage_pending_deletes WHERE id=?`, id)
	return err
}

func (r objectStorageRepo) DeferPendingDelete(ctx context.Context, id int64, notBefore time.Time) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_pending_deletes SET attempts=attempts+1, not_before=? WHERE id=?`, notBefore, id)
	return err
}

func (r objectStorageRepo) UsageByLocation(ctx context.Context) ([]ports.LocationCount, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT storage_id,COUNT(*),COALESCE(SUM(size),0) FROM files GROUP BY storage_id ORDER BY storage_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.LocationCount
	for rows.Next() {
		var u ports.LocationCount
		if err := rows.Scan(&u.ID, &u.Files, &u.Bytes); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r objectStorageRepo) FilesOutside(ctx context.Context, target int64) ([]int64, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT id FROM files WHERE storage_id<>? ORDER BY id`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (r objectStorageRepo) CountFilesOutside(ctx context.Context, target int64) (int64, error) {
	var n int64
	err := r.q.QueryRowContext(ctx, `SELECT COUNT(*) FROM files WHERE storage_id<>?`, target).Scan(&n)
	return n, err
}

func (r objectStorageRepo) MigrationFile(ctx context.Context, id int64) (ports.MigrationFile, error) {
	var f ports.MigrationFile
	var shareID int64
	err := r.q.QueryRowContext(ctx, `SELECT f.id,f.size,f.storage_id,f.sha256,f.enc_id,f.object_key,f.disk_path,f.name,f.enc,s.long_id,s.id FROM files f JOIN shares s ON s.id=f.share_id WHERE f.id=?`, id).
		Scan(&f.ID, &f.Size, &f.LocationID, &f.SHA256, &f.EncID, &f.ObjectKey, &f.DiskPath, &f.Name, &f.Encrypted, &f.ShareLongID, &shareID)
	if err != nil {
		return f, notFound(err)
	}
	if f.SHA256, err = openCol(r.codec, "files", "sha256", f.ID, f.SHA256); err != nil {
		return f, err
	}
	if f.ShareLongID, err = openCol(r.codec, "shares", "long_id", shareID, f.ShareLongID); err != nil {
		return f, err
	}
	f.Name, err = openCol(r.codec, "files", "name", f.ID, f.Name)
	return f, err
}

func (r objectStorageRepo) ListMigrationFiles(ctx context.Context, after int64, limit int) ([]ports.MigrationFile, error) {
	rows, err := r.q.QueryContext(ctx, `SELECT f.id,f.size,f.storage_id,f.sha256,f.enc_id,f.object_key,f.disk_path,f.name,f.enc,s.long_id,s.id FROM files f JOIN shares s ON s.id=f.share_id WHERE f.id>? ORDER BY f.id LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.MigrationFile
	for rows.Next() {
		var f ports.MigrationFile
		var shareID int64
		if err := rows.Scan(&f.ID, &f.Size, &f.LocationID, &f.SHA256, &f.EncID, &f.ObjectKey, &f.DiskPath, &f.Name, &f.Encrypted, &f.ShareLongID, &shareID); err != nil {
			return nil, err
		}
		if f.SHA256, err = openCol(r.codec, "files", "sha256", f.ID, f.SHA256); err != nil {
			return nil, err
		}
		if f.ShareLongID, err = openCol(r.codec, "shares", "long_id", shareID, f.ShareLongID); err != nil {
			return nil, err
		}
		if f.Name, err = openCol(r.codec, "files", "name", f.ID, f.Name); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (r objectStorageRepo) MoveFile(ctx context.Context, f ports.MigrationFile, to ports.MovedFile) (int64, error) {
	sum, err := sealCol(r.codec, "files", "sha256", f.ID, to.SHA256)
	if err != nil {
		return 0, err
	}
	return changed(r.q.ExecContext(ctx, `UPDATE files SET storage_id=?,object_key=?,disk_path=?,enc=?,enc_id=?,sha256=? WHERE id=? AND storage_id=? AND object_key=? AND disk_path=? AND enc_id=?`,
		to.LocationID, to.ObjectKey, to.DiskPath, to.Encrypted, to.EncID, sum, f.ID, f.LocationID, f.ObjectKey, f.DiskPath, f.EncID))
}

type storageMigrationRepo struct{ q querier }

func (r storageMigrationRepo) Start(ctx context.Context, target int64, targetDesc, startedBy string) (int64, error) {
	res, err := r.q.ExecContext(ctx, `INSERT INTO storage_migrations(status,target_location,target,started_by) VALUES('running',?,?,?)`, target, targetDesc, startedBy)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

func (r storageMigrationRepo) StartByTool(ctx context.Context, target int64, targetDesc string) (int64, error) {
	res, err := r.q.ExecContext(ctx, `INSERT INTO storage_migrations(status,target_location,target,started_by) VALUES('running',?,?,'sendora-db')`, target, targetDesc)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	return id, nil
}

func (r storageMigrationRepo) Progress(ctx context.Context, id, total, done, failed, bytes int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET total=?,done=?,failed=?,bytes=? WHERE id=?`, total, done, failed, bytes, id)
	return err
}

func (r storageMigrationRepo) Finish(ctx context.Context, id int64, status, errText string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET status=?,error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?`, status, errText, id)
	return err
}

func (r storageMigrationRepo) FinishWithCounters(ctx context.Context, id int64, status string, total, done, failed, bytes int64, errText string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET status=?,total=?,done=?,failed=?,bytes=?,error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?`, status, total, done, failed, bytes, errText, id)
	return err
}

func (r storageMigrationRepo) FailInterrupted(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET status='failed',error='interrupted by a restart',finished_at=CURRENT_TIMESTAMP WHERE status='running'`)
	return err
}

func (r storageMigrationRepo) Latest(ctx context.Context) (ports.StorageMigration, error) {
	var m ports.StorageMigration
	err := r.q.QueryRowContext(ctx, `SELECT id,status,target_location,target,total,done,failed,bytes,started_by,started_at,finished_at,error FROM storage_migrations ORDER BY id DESC LIMIT 1`).
		Scan(&m.ID, &m.Status, &m.TargetLocation, &m.Target, &m.Total, &m.Done, &m.Failed, &m.Bytes, &m.StartedBy, &m.StartedAt, &m.FinishedAt, &m.Error)
	return m, notFound(err)
}

// ensureSealed is EnsureLocation with a codec: the row is created (or found by
// its identity) first, because the sealed configuration is bound to the row id,
// and the configuration is rewritten only when it changed.
func (r objectStorageRepo) ensureSealed(ctx context.Context, backend, identity, config string) (int64, error) {
	var id int64
	err := r.q.QueryRowContext(ctx, `INSERT INTO storage_locations(backend,identity,config) VALUES(?,?,'')
		ON CONFLICT(identity) DO UPDATE SET identity=excluded.identity
		RETURNING id`, backend, identity).Scan(&id)
	if err != nil {
		return 0, err
	}
	cur, err := r.LocationConfig(ctx, id)
	if err != nil {
		return 0, err
	}
	if cur == config {
		return id, nil
	}
	sealed, err := sealCol(r.codec, "storage_locations", "config", id, config)
	if err != nil {
		return 0, err
	}
	_, err = r.q.ExecContext(ctx, `UPDATE storage_locations SET config=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, sealed, id)
	return id, err
}
