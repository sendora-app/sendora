// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure helpers for the audit log page: query building, local date range, paging and labels.
import { tr } from './i18n/mark.mjs'

export const AUDIT_PAGE_SIZE = 50
export const blankAuditFilters = () => ({ q: '', category: '', action: '', actor: '', outcome: '', from: '', to: '' })
export const hasAuditFilters = f => Object.values(f || {}).some(v => String(v ?? '').trim() !== '')

const DATE = /^(\d{4})-(\d{2})-(\d{2})$/
// RFC 3339 in UTC without milliseconds, e.g. 2026-11-17T23:00:00Z.
const rfc3339 = d => d.toISOString().replace(/\.\d{3}Z$/, 'Z')
// A YYYY-MM-DD date from <input type=date> means a day in the viewer's time zone.
// localDayStart gives its local midnight, localNextDayStart the local midnight of the
// following day (built from the calendar, so days of 23 or 25 hours stay correct).
function localDate(value, addDays = 0) {
  const m = DATE.exec(String(value || ''))
  if (!m) return null
  const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + addDays, 0, 0, 0, 0)
  return Number.isNaN(d.getTime()) ? null : rfc3339(d)
}
export const localDayStart = value => localDate(value, 0)
export const localNextDayStart = value => localDate(value, 1)

// Query parameters for /audit and /audit/export from the last submitted filters.
export function auditParams(filters, extra = {}) {
  const params = new URLSearchParams()
  for (const [k, v] of Object.entries(filters || {})) {
    const value = String(v ?? '').trim()
    if (!value) continue
    if (k === 'from') { const x = localDayStart(value); if (x) params.set('from', x) }
    else if (k === 'to') { const x = localNextDayStart(value); if (x) params.set('to', x) }
    else params.set(k, value)
  }
  for (const [k, v] of Object.entries(extra)) params.set(k, String(v))
  return params
}

// Pager numbers: "{from}-{to} of {total}"; total is shown as a lower bound when capped.
export function pagerInfo(offset, count, total, capped = false) {
  if (!count) return { from: 0, to: 0, total, capped: !!capped }
  return { from: offset + 1, to: offset + count, total, capped: !!capped }
}
// The offset of the last page that still has records (0 when there are none).
export const lastPageOffset = (total, limit = AUDIT_PAGE_SIZE) => total > 0 ? Math.floor((total - 1) / limit) * limit : 0
// After a refresh the current page may lie past the end (records purged or filtered away).
export const needsClamp = (offset, count, total) => offset > 0 && count === 0 && total >= 0 && offset >= total

// Action names the server writes (the action filter matches exactly). The page adds the
// actions it has seen on the loaded page.
export const KNOWN_ACTIONS = [
  'access_denied', 'audit_exported', 'audit_purge_failed', 'audit_purged', 'audit_viewed', 'backup_created',
  'backup_deleted', 'backup_remote_copied', 'backup_remote_failed', 'backup_remote_pruned',
  'db_import_applied', 'db_import_prepared', 'download_started', 'file_decrypt_failed', 'invite_accepted',
  'invite_created', 'invite_revoked', 'ip_banned', 'ip_unbanned', 'key_fingerprint_changed', 'login_failed',
  'login_lockout', 'login_ok', 'logout', 'mfa_enrolled', 'mfa_failed', 'mfa_login_ok', 'mfa_policy_changed',
  'mfa_removed', 'mfa_reset', 'mfa_reset_confirmed', 'mfa_reset_requested', 'password_changed',
  'password_expired', 'password_expiry_warning_sent', 'password_reset', 'password_rotation_exempt_changed',
  'provider_created', 'provider_deleted', 'provider_updated', 'session_reuse_detected', 'settings_changed',
  'share_created', 'share_deleted', 'share_edited', 'share_expired_manual', 'share_expiry_changed',
  'share_extended', 'share_file_removed', 'share_files_added', 'share_limit_changed', 'share_preview',
  'storage_backend_changed', 'storage_connection_test_failed', 'storage_connection_tested',
  'storage_migration_cancel_requested', 'storage_migration_cancelled', 'storage_migration_failed',
  'storage_migration_finished', 'storage_migration_requested', 'storage_migration_started', 'system_start',
  'system_stop', 'ui_language_deleted', 'ui_language_imported', 'user_created', 'user_deleted',
  'user_email_changed', 'user_force_reset', 'user_password_reset_sent', 'user_role_changed', 'user_unlocked',
  'user_updated', 'user_welcome',
]
export function actionSuggestions(records = [], known = KNOWN_ACTIONS) {
  const set = new Set(known)
  for (const r of records) if (r && typeof r.action === 'string' && r.action) set.add(r.action)
  return [...set].sort()
}

export const AUDIT_CATEGORIES = ['auth', 'account', 'admin', 'security', 'share', 'system']
export const AUDIT_OUTCOMES = ['ok', 'denied', 'failed', 'attempted']
export const categoryLabels = { auth: tr('Sign-in'), account: tr('Accounts'), admin: tr('Administration'), security: tr('Security'), share: tr('Shares'), system: tr('System') }
export const outcomeLabels = { ok: tr('Succeeded'), denied: tr('Denied'), failed: tr('Failed'), attempted: tr('Attempted') }
export const roleLabels = { admin: tr('Administrator'), auditor: tr('Auditor'), user: tr('User'), guest: tr('Guest'), system: tr('System'), anonymous: tr('Anonymous') }
export const chainReasonLabels = {
  'checkpoint row missing': tr('checkpoint row missing'),
  'checkpoint modified': tr('checkpoint modified'),
  'record out of sequence': tr('record out of sequence'),
  'record missing': tr('record missing'),
  'chain link broken': tr('chain link broken'),
  'record modified or forged': tr('record modified or forged'),
  'newest records removed': tr('newest records removed'),
}
// English label for a code (translate with t()); unknown codes are shown as they are.
export const labelFor = (map, code) => (code && Object.hasOwn(map, code) ? map[code] : code || '')
