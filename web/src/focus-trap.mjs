// SPDX-License-Identifier: AGPL-3.0-or-later

// A small focus trap for modal dialogs: focus the first control on open, keep Tab and
// Shift+Tab inside, optional Escape handler, and give focus back on close.

// Where Tab should move to, given the focused control's index among `count` focusable
// controls; -1 means the browser's own move is fine (it stays inside the dialog).
export function wrapFocusIndex(current, count, backwards) {
  if (count <= 0) return -1
  if (current < 0) return backwards ? count - 1 : 0
  if (backwards && current === 0) return count - 1
  if (!backwards && current === count - 1) return 0
  return -1
}

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])'
const focusables = el => [...el.querySelectorAll(FOCUSABLE)].filter(x => !x.hidden && x.getClientRects().length > 0)

// A trap leaves the keys alone while focus sits in another modal dialog (for example the
// step-up prompt opened over a form): that dialog runs its own trap.
export function otherModalHasFocus(el, active) {
  if (!active || el.contains(active)) return false
  const modal = active.closest?.('[aria-modal="true"]')
  return !!modal && modal !== el
}

export function createFocusTrap(el, { onEscape } = {}) {
  const previous = document.activeElement
  const first = focusables(el)[0]
  ;(first || el).focus?.()
  function onKey(e) {
    if (otherModalHasFocus(el, document.activeElement)) return
    if (e.key === 'Escape' && onEscape) { e.preventDefault(); onEscape(); return }
    if (e.key !== 'Tab') return
    const list = focusables(el)
    const next = wrapFocusIndex(list.indexOf(document.activeElement), list.length, e.shiftKey)
    if (list.length === 0) { e.preventDefault(); return }
    if (next >= 0) { e.preventDefault(); list[next].focus() }
  }
  document.addEventListener('keydown', onKey, true)
  return {
    release() {
      document.removeEventListener('keydown', onKey, true)
      // Only give focus back when it is still ours to give: another dialog may have taken it.
      const active = document.activeElement
      const ours = !active || active === document.body || el.contains(active)
      if (ours && previous && previous.isConnected && typeof previous.focus === 'function') previous.focus()
    },
  }
}

// Vue directive: v-focus-trap or v-focus-trap="onEscape".
export const vFocusTrap = {
  mounted(el, binding) {
    el._focusTrap = createFocusTrap(el, { onEscape: typeof binding.value === 'function' ? () => el._focusTrapEscape?.() : null })
    el._focusTrapEscape = binding.value
  },
  updated(el, binding) { el._focusTrapEscape = binding.value },
  unmounted(el) { el._focusTrap?.release(); el._focusTrap = null },
}
