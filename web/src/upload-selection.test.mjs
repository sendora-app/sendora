// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { collect, fromInput } from './upload-selection.js'
const file = (name, path = '') => ({ name, webkitRelativePath: path })
const leaf = name => ({ name, isFile: true, file: resolve => resolve(file(name)) })
const dir = (name, batches) => ({ name, isDirectory: true, createReader() { let index = 0; return { readEntries(resolve) { resolve(batches[index++] || []) } } } })
test('folder picker excludes hidden files and hidden ancestors only', () => {
  const selected = fromInput([file('visible.txt','docs/visible.txt'),file('.env','docs/.env'),file('config','docs/.git/config'),file('visible.txt','.secret/visible.txt'),file('report.v2.txt','docs/report.v2.txt'),file('.env')])
  assert.deepEqual(selected.map(entry=>entry.path),['docs/visible.txt','docs/report.v2.txt','.env'])
})
test('folder drop skips hidden trees before reading and handles multiple batches', async () => {
  const forbidden = { name: '.git', isDirectory: true, createReader() { throw new Error('must not read hidden directory') } }
  const hiddenFile = { name: '.env', isFile: true, file() { throw new Error('must not read hidden file') } }
  const root = dir('docs',[[leaf('one.txt'),forbidden,hiddenFile],[dir('nested',[[leaf('two.txt'),leaf('.DS_Store')]])]])
  const selected = await collect({items:[{webkitGetAsEntry:()=>root}],files:[]})
  assert.deepEqual(selected.map(entry=>entry.path),['docs/one.txt','docs/nested/two.txt'])
})
test('folder uploads exclude Windows and Office temporary files across extensions', async () => {
  const names = ['~x.docx', '~$budget.xlsx', '~slides.pptx', 'cache.tmp', 'CACHE.TEMP', 'Thumbs.db', 'desktop.ini', 'report.docx', 'backup.bak', 'project.lock']
  const expected = ['docs/report.docx', 'docs/backup.bak', 'docs/project.lock']
  assert.deepEqual(fromInput(names.map(name => file(name, 'docs/' + name))).map(entry => entry.path), expected)
  const root = dir('docs', [names.map(leaf)])
  assert.deepEqual((await collect({items:[{webkitGetAsEntry:()=>root}]})).map(entry => entry.path), expected)
  assert.equal(fromInput([file('~x.docx')]).length, 1)
})
test('explicit hidden standalone files allowed, hidden root directories skipped', async () => {
  const selected = await collect({items:[{webkitGetAsEntry:()=>leaf('.env')},{webkitGetAsEntry:()=>dir('.private',[[leaf('secret.txt')]])}]})
  assert.deepEqual(selected.map(entry=>entry.path),['.env'])
  assert.deepEqual((await collect({files:[file('.env')]})).map(entry=>entry.path),['.env'])
})
