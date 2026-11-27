// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { splitHostPort, validHost, validPort, joinHostPort, defaultPort, platformURLs, portWarning } from './base-domain.mjs'

test('split what administrators type or paste', () => {
  assert.deepEqual(splitHostPort('sendora.localhost'), { host: 'sendora.localhost', port: '' })
  assert.deepEqual(splitHostPort('sendora.localhost:9090'), { host: 'sendora.localhost', port: '9090' })
  assert.deepEqual(splitHostPort('https://Files.Example.com:8443/path?x=1'), { host: 'files.example.com', port: '8443' })
  assert.deepEqual(splitHostPort('  http://user@host.example/ '), { host: 'host.example', port: '' })
  assert.deepEqual(splitHostPort('example.com.'), { host: 'example.com', port: '' })
})

test('host and port validation', () => {
  for (const ok of ['localhost', 'sendora.localhost', 'files.example.com']) assert.ok(validHost(ok), ok)
  for (const bad of ['', 'a..b', '-x.example', 'x_y.example', 'exa mple.com', 'x'.repeat(64) + '.com']) assert.ok(!validHost(bad), bad)
  assert.ok(!validHost('localhost', { minLabels: 2 }))
  for (const ok of ['', '1', '9090', '65535']) assert.ok(validPort(ok), ok)
  for (const bad of ['0', '65536', 'x', '-1', '123456']) assert.ok(!validPort(bad), bad)
})

test('stored form and prefill', () => {
  assert.equal(joinHostPort('sendora.localhost', '9090'), 'sendora.localhost:9090')
  assert.equal(joinHostPort('example.com', ''), 'example.com')
  assert.equal(joinHostPort('example.com', '443'), 'example.com')
  assert.equal(defaultPort('9090'), '9090')
  assert.equal(defaultPort(''), '')
  assert.equal(defaultPort('443'), '')
})

test('resulting addresses and port warnings', () => {
  assert.deepEqual(platformURLs('sendora.localhost', '9090', 'acme'), { console: 'http://admin.sendora.localhost:9090', org: 'http://acme.sendora.localhost:9090' })
  assert.deepEqual(platformURLs('files.example.com', '', 'acme'), { console: 'https://admin.files.example.com', org: 'https://acme.files.example.com' })
  assert.equal(platformURLs('bad host', '', 'a'), null)
  assert.equal(portWarning('', '9090'), 'missing-port')
  assert.equal(portWarning('9090', '9090'), '')
  assert.equal(portWarning('8443', ''), 'extra-port')
  assert.equal(portWarning('', ''), '')
})
