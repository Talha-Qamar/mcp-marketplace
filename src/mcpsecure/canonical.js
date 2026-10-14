/**
 * MCP Secure — Canonical JSON
 * ============================
 * Recursive key-sorted JSON, so the same value always hashes to the same bytes
 * regardless of property insertion order. Used for content fingerprints and
 * finding ids. (Attestation signing still uses the legacy serialisation; moving
 * it to this function is deferred with the blockchain work, spec §8.1.)
 *
 * Only plain JSON values are accepted: objects, arrays, strings, finite
 * numbers, booleans and null. `undefined` object members are dropped, as
 * JSON.stringify does.
 */

const crypto = require('crypto');

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonicalJson: non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(v => (v === undefined ? 'null' : canonicalJson(v))).join(',') + ']';
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value).filter(k => value[k] !== undefined).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
  }
  throw new TypeError(`canonicalJson: unsupported type ${typeof value}`);
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** `sha256:<hex>` of the canonical JSON of `value`. */
function canonicalDigest(value) {
  return 'sha256:' + sha256Hex(canonicalJson(value));
}

module.exports = { canonicalJson, canonicalDigest, sha256Hex };
