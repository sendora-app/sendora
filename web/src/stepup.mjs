// SPDX-License-Identifier: AGPL-3.0-or-later

// Step-up re-authentication helpers (pure, unit tested).

// A 401/403 body that asks for a re-authentication of a critical action.
export const isStepUpResponse = data => !!data && data.code === 'stepup_required'

// What the dialog shows: 'reauth' (sign in again at the provider), or the first
// usable method. The second factor is preferred; passkeys only where supported.
export function stepUpChoices(data, passkeySupported = false) {
  if (!data || data.reauth) return { mode: 'reauth', methods: [] }
  const methods = (data.methods || []).filter(m => m === 'totp' || m === 'password' || (m === 'webauthn' && passkeySupported))
  if (!methods.length) return { mode: 'reauth', methods: [] }
  return { mode: methods[0], methods }
}

// The body sent to POST /api/auth/step-up for the chosen mode.
export function stepUpBody(mode, value) {
  if (mode === 'totp') return { code: String(value || '').replace(/\s+/g, '') }
  if (mode === 'password') return { password: String(value || '') }
  return {}
}
