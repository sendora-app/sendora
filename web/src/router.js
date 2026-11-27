// SPDX-License-Identifier: AGPL-3.0-or-later

import { createRouter, createWebHistory } from 'vue-router'
import { session } from './api'
import { app } from './state'

// meta.public: pages reached from an email or a link that work with or without a
// session; signed-in auditors and guests are not redirected away from them.
const routes = [
  { path: '/', component: () => import('./views/Upload.vue'), meta: { auth: true } },
  { path: '/login', component: () => import('./views/Login.vue'), meta: { public: true } },
  { path: '/setup', component: () => import('./views/Setup.vue') },
  { path: '/register', component: () => import('./views/Register.vue') },
  { path: '/forgot-password', component: () => import('./views/Forgot.vue'), meta: { public: true } },
  { path: '/reset-password/:token', component: () => import('./views/Reset.vue'), meta: { public: true } },
  { path: '/mfa-reset/:token', component: () => import('./views/MfaResetConfirm.vue'), meta: { public: true } },
  { path: '/share/:id', component: () => import('./views/Share.vue'), meta: { public: true } },
  { path: '/invite/:token', component: () => import('./views/Invite.vue') },
  { path: '/shares', component: () => import('./views/MyShares.vue'), meta: { auth: true } },
  { path: '/profile', component: () => import('./views/Profile.vue'), meta: { auth: true } },
  { path: '/audit', component: () => import('./views/Audit.vue'), meta: { auth: true, auditor: true } },
  { path: '/access-review', component: () => import('./views/admin/AccessReview.vue'), meta: { auth: true, auditor: true } },
  {
    path: '/admin', component: () => import('./views/admin/Admin.vue'), meta: { auth: true, admin: true },
    children: [
      { path: '', redirect: '/admin/stats' },
      { path: 'stats', component: () => import('./views/admin/Stats.vue') },
      { path: 'users', component: () => import('./views/admin/Users.vue') },
      { path: 'access-review', component: () => import('./views/admin/AccessReview.vue') },
      { path: 'settings', component: () => import('./views/admin/SettingsView.vue') },
      { path: 'branding', component: () => import('./views/admin/Branding.vue') },
      { path: 'themes', component: () => import('./views/admin/Themes.vue') },
      { path: 'providers', component: () => import('./views/admin/Providers.vue') },
      { path: 'emails', component: () => import('./views/admin/Emails.vue') },
      { path: 'security', component: () => import('./views/admin/Security.vue') },
      { path: 'languages', component: () => import('./views/admin/Languages.vue') },
      { path: 'backups', component: () => import('./views/admin/Backups.vue') },
      { path: 'storage', component: () => import('./views/admin/Storage.vue') },
      { path: 'keys', component: () => import('./views/admin/Keys.vue') },
      { path: 'multitenant', component: () => import('./views/admin/MultiTenant.vue') },
      { path: 'logs', component: () => import('./views/Audit.vue') }
    ]
  },
  { path: '/:pathMatch(.*)*', redirect: '/' }
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(to => {
  if (app.boot?.setup_needed && to.path !== '/setup') return '/setup'
  if (to.meta.auth && !session.user) return { path: '/login', query: { next: to.fullPath } }
  if (to.meta.auth && (session.user?.must_change_password || session.user?.mfa_enroll_required) && to.path !== '/profile') return '/profile'
  if (to.meta.admin && !session.user?.admin) return '/'
  if (to.meta.auditor && !session.user?.auditor) return '/'
  // Auditor accounts are read-only: they only see the audit log and their profile.
  if (session.user?.auditor && !['/audit', '/access-review', '/profile'].includes(to.path) && !to.meta.public) return '/audit'
  if (session.user?.is_guest && !['/', '/invite'].some(p => to.path === p || to.path.startsWith('/invite/')) && !to.meta.public) return '/'
})
export default router
