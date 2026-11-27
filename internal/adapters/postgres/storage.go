// SPDX-License-Identifier: AGPL-3.0-or-later

package postgres

import (
	"context"
	"time"

	"github.com/sendora-app/sendora/internal/ports"
)

type objectStorageRepo struct {
	q     pq
	codec ports.ColumnCodec
}

func (r objectStorageRepo) EnsureLocation(ctx context.Context, backend, identity, config string) (int64, error) {
	if r.codec != nil {
		return r.ensureSealed(ctx, backend, identity, config)
	}
	var id int64
	err := r.q.scan(ctx, `INSERT INTO storage_locations(backend,identity,config) VALUES(?,?,?)
		ON CONFLICT(identity) DO UPDATE SET config=excluded.config, updated_at=CASE WHEN storage_locations.config<>excluded.config THEN date_trunc('second', now()) ELSE storage_locations.updated_at END
		RETURNING id`, []any{backend, identity, config}, &id)
	return id, err
}

func (r objectStorageRepo) LocationConfig(ctx context.Context, id int64) (string, error) {
	var js string
	err := r.q.scan(ctx, `SELECT config FROM storage_locations WHERE id=?`, []any{id}, &js)
	if err != nil {
		return js, err
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
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM storage_pending_deletes`, nil, &n)
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
	rows, err := r.q.QueryContext(ctx, `SELECT storage_id,COUNT(*),COALESCE(SUM(size),0)::bigint FROM files GROUP BY storage_id ORDER BY storage_id`)
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
	err := r.q.scan(ctx, `SELECT COUNT(*) FROM files WHERE storage_id<>?`, []any{target}, &n)
	return n, err
}

func (r objectStorageRepo) MigrationFile(ctx context.Context, id int64) (ports.MigrationFile, error) {
	var f ports.MigrationFile
	var shareID int64
	err := r.q.scan(ctx, `SELECT f.id,f.size,f.storage_id,f.sha256,f.enc_id,f.object_key,f.disk_path,f.name,f.enc,s.long_id,s.id FROM files f JOIN shares s ON s.id=f.share_id WHERE f.id=?`, []any{id},
		&f.ID, &f.Size, &f.LocationID, &f.SHA256, &f.EncID, &f.ObjectKey, &f.DiskPath, &f.Name, &f.Encrypted, &f.ShareLongID, &shareID)
	if err != nil {
		return f, err
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

type storageMigrationRepo struct{ q pq }

func (r storageMigrationRepo) Start(ctx context.Context, target int64, targetDesc, startedBy string) (int64, error) {
	return insertID(ctx, r.q, `INSERT INTO storage_migrations(status,target_location,target,started_by) VALUES('running',?,?,?) RETURNING id`, target, targetDesc, startedBy)
}

func (r storageMigrationRepo) StartByTool(ctx context.Context, target int64, targetDesc string) (int64, error) {
	return insertID(ctx, r.q, `INSERT INTO storage_migrations(status,target_location,target,started_by) VALUES('running',?,?,'sendora-db') RETURNING id`, target, targetDesc)
}

func (r storageMigrationRepo) Progress(ctx context.Context, id, total, done, failed, bytes int64) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET total=?,done=?,failed=?,bytes=? WHERE id=?`, total, done, failed, bytes, id)
	return err
}

func (r storageMigrationRepo) Finish(ctx context.Context, id int64, status, errText string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET status=?,error=?,finished_at=date_trunc('second', now()) WHERE id=?`, status, errText, id)
	return err
}

func (r storageMigrationRepo) FinishWithCounters(ctx context.Context, id int64, status string, total, done, failed, bytes int64, errText string) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET status=?,total=?,done=?,failed=?,bytes=?,error=?,finished_at=date_trunc('second', now()) WHERE id=?`, status, total, done, failed, bytes, errText, id)
	return err
}

func (r storageMigrationRepo) FailInterrupted(ctx context.Context) error {
	_, err := r.q.ExecContext(ctx, `UPDATE storage_migrations SET status='failed',error='interrupted by a restart',finished_at=date_trunc('second', now()) WHERE status='running'`)
	return err
}

func (r storageMigrationRepo) Latest(ctx context.Context) (ports.StorageMigration, error) {
	var m ports.StorageMigration
	err := r.q.scan(ctx, `SELECT id,status,target_location,target,total,done,failed,bytes,started_by,started_at,finished_at,error FROM storage_migrations ORDER BY id DESC LIMIT 1`, nil,
		&m.ID, &m.Status, &m.TargetLocation, &m.Target, &m.Total, &m.Done, &m.Failed, &m.Bytes, &m.StartedBy, &m.StartedAt, &m.FinishedAt, &m.Error)
	return m, err
}

// ensureSealed is EnsureLocation with a codec: the row is created (or found by
// its identity) first, because the sealed configuration is bound to the row id,
// and the configuration is rewritten only when it changed.
func (r objectStorageRepo) ensureSealed(ctx context.Context, backend, identity, config string) (int64, error) {
	var id int64
	err := r.q.scan(ctx, `INSERT INTO storage_locations(backend,identity,config) VALUES(?,?,'')
		ON CONFLICT(identity) DO UPDATE SET identity=excluded.identity
		RETURNING id`, []any{backend, identity}, &id)
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
	_, err = r.q.ExecContext(ctx, `UPDATE storage_locations SET config=?, updated_at=date_trunc('second', now()) WHERE id=?`, sealed, id)
	return id, err
}
