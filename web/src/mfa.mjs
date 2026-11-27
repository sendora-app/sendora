// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure helpers for the MFA screens. The server stays authoritative; this only
// shapes input/output for forms and the WebAuthn browser API.

import { tr } from './i18n/mark.mjs'

const B64URL = /^[A-Za-z0-9_-]*$/

export function b64urlEncode(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input)
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(bin).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '')
}

// Strict: base64url alphabet only (padding tolerated), throws on anything else.
export function b64urlDecode(text) {
  const s = String(text ?? '').replace(/=+$/, '')
  if (!B64URL.test(s) || s.length % 4 === 1) throw new TypeError('invalid base64url')
  const bin = atob(s.replaceAll('-', '+').replaceAll('_', '/'))
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

const descriptor = d => ({ ...d, id: b64urlDecode(d.id) })

// Server JSON → argument for navigator.credentials.create().
export function creationArgs(options) {
  return {
    publicKey: {
      ...options,
      challenge: b64urlDecode(options.challenge),
      user: { ...options.user, id: b64urlDecode(options.user.id) },
      excludeCredentials: (options.excludeCredentials || []).map(descriptor),
    },
  }
}

// Server JSON → argument for navigator.credentials.get().
export function requestArgs(options) {
  return {
    publicKey: {
      ...options,
      challenge: b64urlDecode(options.challenge),
      allowCredentials: (options.allowCredentials || []).map(descriptor),
    },
  }
}

// PublicKeyCredential (registration) → JSON contract.
export function registrationJSON(cred) {
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64urlEncode(cred.response.clientDataJSON),
      attestationObject: b64urlEncode(cred.response.attestationObject),
    },
  }
}

// PublicKeyCredential (assertion) → JSON contract.
export function assertionJSON(cred) {
  const handle = cred.response.userHandle
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64urlEncode(cred.response.clientDataJSON),
      authenticatorData: b64urlEncode(cred.response.authenticatorData),
      signature: b64urlEncode(cred.response.signature),
      userHandle: handle && handle.byteLength ? b64urlEncode(handle) : null,
    },
  }
}

// Authenticator code: 6 digits, spaces and dashes allowed while typing.
export function normalizeTotp(input) {
  const code = String(input ?? '').replace(/[\s-]+/g, '')
  return /^\d{6}$/.test(code) ? { ok: true, code } : { ok: false, code }
}

// Recovery code: 16 letters/digits, shown as 4-4-4-4; spaces, dashes and case are ignored.
export function normalizeRecovery(input) {
  const code = String(input ?? '').replace(/[\s-]+/g, '').toUpperCase()
  return /^[A-Z0-9]{16}$/.test(code) ? { ok: true, code } : { ok: false, code }
}

export function groupRecovery(code) {
  const c = String(code ?? '').replace(/[\s-]+/g, '').toUpperCase()
  return c.match(/.{1,4}/g)?.join('-') ?? ''
}

// `t` is the UI translator (identity by default) so the downloaded file follows the menu language.
export function recoveryFileText(codes, appName = 'Sendora', t = key => key) {
  return [t('{app} recovery codes').replaceAll('{app}', appName), t('Each code works once. Keep them somewhere safe.'), '', ...codes.map(groupRecovery), ''].join('\n')
}

// Returns an English i18n key for a WebAuthn browser error.
export function webauthnErrorKey(error) {
  switch (error?.name) {
    case 'NotAllowedError': return tr('The passkey request was cancelled or timed out.')
    case 'InvalidStateError': return tr('This security key or passkey is already registered.')
    case 'SecurityError': return tr('Passkeys need a secure page (https or localhost).')
    case 'NotSupportedError': return tr('This device or browser does not support the requested key type.')
    case 'AbortError': return tr('The passkey request was interrupted.')
    case 'ConstraintError': return tr('This device cannot satisfy the required security options.')
    case 'TypeError': case 'SyntaxError': return tr('The server sent an invalid passkey request.')
    default: return tr('The passkey request failed.')
  }
}

export const webauthnSupported = () => typeof navigator !== 'undefined' && !!navigator.credentials && typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function'
