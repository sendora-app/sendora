// SPDX-License-Identifier: AGPL-3.0-or-later

import test from 'node:test'
import assert from 'node:assert/strict'
import { buildTree, visibleRows, bytesDonePerFile, folderDone, folderPaths, extensionOf, fileKind } from './folder-tree.mjs'

const items = [
  { path: 'docs/b.txt', size: 10 }, { path: 'docs/sub/a.json', size: 5 }, { path: 'docs/sub/deep/x.png', size: 1 },
  { path: 'root.zip', size: 100 }, { path: 'docs/a10.txt', size: 2 }, { path: 'docs/a2.txt', size: 3 },
]
test('totals roll up into every ancestor folder', () => {
  const root = buildTree(items)
  assert.equal(root.files, 6); assert.equal(root.bytes, 121); assert.equal(root.folders, 3)
  const docs = root.children[0]
  assert.equal(docs.name, 'docs'); assert.equal(docs.files, 5); assert.equal(docs.bytes, 21); assert.equal(docs.folders, 2)
})
test('folders sort first, names sort naturally, depth is set', () => {
  const root = buildTree(items)
  assert.deepEqual(root.children.map(c => c.name), ['docs', 'root.zip'])
  const docs = root.children[0]
  assert.deepEqual(docs.children.map(c => c.name), ['sub', 'a2.txt', 'a10.txt', 'b.txt'])
  assert.equal(docs.children[0].children[0].depth, 2)
})
test('visibleRows honours open overrides', () => {
  const big = Array.from({ length: 60 }, (_, i) => ({ path: `a/b/f${i}.txt`, size: 1 }))
  const root = buildTree(big)
  assert.deepEqual(visibleRows(root).map(r => r.name), ['a', 'b'])
  assert.equal(visibleRows(root, { 'a/b': true }).length, 62)
  assert.equal(visibleRows(root, { a: false }).length, 1)
  assert.deepEqual(folderPaths(root), ['a', 'a/b'])
})
test('overall progress maps onto sequentially uploaded files', () => {
  assert.deepEqual(bytesDonePerFile([10, 20, 30], 0), [0, 0, 0])
  assert.deepEqual(bytesDonePerFile([10, 20, 30], 25), [10, 15, 0])
  assert.deepEqual(bytesDonePerFile([10, 20, 30], 60), [10, 20, 30])
  const list = [{ path: 'd/a', size: 10 }, { path: 'd/b', size: 20 }, { path: 'z', size: 30 }]
  const root = buildTree(list)
  const done = new Map(list.map((it, i) => [it, bytesDonePerFile(list.map(x => x.size), 25)[i]]))
  assert.equal(folderDone(root.children[0], it => done.get(it)), 25)
})
test('extension and kind', () => {
  assert.equal(extensionOf('spring-theme.json'), 'json'); assert.equal(extensionOf('.env'), ''); assert.equal(extensionOf('README'), '')
  assert.equal(fileKind('a.PNG'), 'image'); assert.equal(fileKind('a.xyz'), 'file')
})
test('ignores empty paths', () => assert.equal(buildTree([{ path: '', size: 1 }]).files, 0))
