const test = require('node:test');
const assert = require('node:assert/strict');
const { canonicalJson, canonicalDigest } = require('../src/mcpsecure/canonical');

test('canonical JSON ignores key insertion order at every depth', () => {
  const a = { b: 1, a: { y: [1, { q: 2, p: 1 }], x: 'z' } };
  const b = { a: { x: 'z', y: [1, { p: 1, q: 2 }] }, b: 1 };
  assert.equal(canonicalJson(a), canonicalJson(b));
  assert.equal(canonicalDigest(a), canonicalDigest(b));
});

test('canonical JSON keeps array order and drops undefined members', () => {
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
  assert.equal(canonicalJson({ a: 1, b: undefined }), '{"a":1}');
});

test('canonical JSON rejects non-JSON numbers', () => {
  assert.throws(() => canonicalJson({ a: NaN }));
});
