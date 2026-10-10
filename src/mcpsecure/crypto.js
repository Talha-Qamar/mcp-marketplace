/**
 * MCP Secure — Real Cryptography Module
 * ======================================
 * ALL operations in this file are real cryptography (not simulated).
 * - SHA-256: Node.js built-in crypto module
 * - Merkle tree: pairwise SHA-256 over sorted leaf pairs
 * - Ed25519: Node.js built-in crypto (Node 15+)
 *
 * The same verification operations are replicated client-side in
 * public/js/mcpsecure.js using the Web Crypto API (crypto.subtle).
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_PATH = path.join(__dirname, '../../database/mcs_key.json');

// ─── SHA-256 ──────────────────────────────────────────────────────────────────

/**
 * Compute real SHA-256 over a UTF-8 string. Returns lowercase hex.
 * @param {string} input
 * @returns {string} 64-char hex
 */
function sha256hex(input) {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

/**
 * Canonicalize a server content object for fingerprinting.
 * Fields are sorted alphabetically so the hash is stable regardless of
 * object key insertion order.
 * @param {object} content
 * @returns {string}
 */
function canonicalize(content) {
  const sorted = {};
  for (const key of Object.keys(content).sort()) {
    sorted[key] = content[key];
  }
  return JSON.stringify(sorted);
}

/**
 * Compute the content fingerprint for a server.
 * @param {object} content - { name, description, long_description, github_url, tools[], ... }
 * @returns {string} sha256 hex
 */
function fingerprintContent(content) {
  return sha256hex(canonicalize(content));
}

// ─── Merkle Tree ──────────────────────────────────────────────────────────────

/**
 * Hash a single leaf: sha256("leaf:" + data)
 * The "leaf:" prefix prevents second-preimage attacks.
 * @param {string} data
 * @returns {string}
 */
function hashLeaf(data) {
  return sha256hex('leaf:' + data);
}

/**
 * Hash two child nodes: sha256("node:" + left + right)
 * @param {string} left
 * @param {string} right
 * @returns {string}
 */
function hashNode(left, right) {
  return sha256hex('node:' + left + right);
}

/**
 * Build a Merkle tree from an array of leaf data strings.
 * Returns the root hash or '0'.repeat(64) for empty.
 * @param {string[]} leaves - raw data strings (not pre-hashed)
 * @returns {{ root: string, leafHashes: string[] }}
 */
function buildMerkleTree(leaves) {
  if (!leaves || leaves.length === 0) {
    return { root: '0'.repeat(64), leafHashes: [] };
  }

  const leafHashes = leaves.map(hashLeaf);

  if (leafHashes.length === 1) {
    return { root: leafHashes[0], leafHashes };
  }

  let level = [...leafHashes];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(hashNode(level[i], level[i + 1]));
      } else {
        // Odd leaf: promote as-is (RFC 6962 style)
        next.push(level[i]);
      }
    }
    level = next;
  }

  return { root: level[0], leafHashes };
}

/**
 * Generate a real Merkle inclusion proof for leafIndex.
 * @param {string[]} leaves - raw data strings
 * @param {number} leafIndex
 * @returns {{ leafIndex: number, siblings: string[], rootHash: string }}
 */
function generateInclusionProof(leaves, leafIndex) {
  const { root, leafHashes } = buildMerkleTree(leaves);

  if (leafIndex < 0 || leafIndex >= leafHashes.length) {
    throw new Error(`leafIndex ${leafIndex} out of range (0..${leafHashes.length - 1})`);
  }

  const siblings = [];
  let level = [...leafHashes];
  let idx = leafIndex;

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        if (i === idx || i + 1 === idx) {
          // Record sibling
          siblings.push(i === idx ? level[i + 1] : level[i]);
          idx = Math.floor(i / 2);
          // Recalculate idx position in next level
        }
        next.push(hashNode(level[i], level[i + 1]));
      } else {
        if (i === idx) idx = next.length;
        next.push(level[i]);
      }
    }
    // Recalculate idx in terms of next level
    idx = Math.floor(leafIndex / Math.pow(2, siblings.length));
    level = next;
  }

  return { leafIndex, siblings, rootHash: root };
}

/**
 * Verify a Merkle inclusion proof.
 * @param {string} leafData - original data (not pre-hashed)
 * @param {number} leafIndex
 * @param {string[]} siblings
 * @param {string} expectedRoot
 * @returns {boolean}
 */
function verifyInclusionProof(leafData, leafIndex, siblings, expectedRoot) {
  try {
    let hash = hashLeaf(leafData);
    let idx = leafIndex;

    for (const sibling of siblings) {
      if (idx % 2 === 0) {
        hash = hashNode(hash, sibling);
      } else {
        hash = hashNode(sibling, hash);
      }
      idx = Math.floor(idx / 2);
    }

    return hash === expectedRoot;
  } catch {
    return false;
  }
}

// ─── Ed25519 Key Management ────────────────────────────────────────────────────

/**
 * Load or generate the persistent Ed25519 signing keypair.
 * The keypair is stored in database/mcs_key.json as hex strings.
 * This is generated ONCE and reused across server restarts so all
 * existing signatures remain verifiable.
 * @returns {{ privateKeyHex: string, publicKeyHex: string, publicKeyId: string }}
 */
function loadOrGenerateKeyPair() {
  if (fs.existsSync(KEY_PATH)) {
    try {
      const data = JSON.parse(fs.readFileSync(KEY_PATH, 'utf8'));
      if (data.privateKeyHex && data.publicKeyHex && data.publicKeyId) {
        return data;
      }
    } catch (e) {
      console.warn('[MCS] Key file corrupt, regenerating.');
    }
  }

  // Generate a new Ed25519 keypair using Node.js built-in crypto
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');

  const privateKeyHex = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('hex');
  const publicKeyHex = publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
  const publicKeyId = 'mcs-ed25519-v1-' + sha256hex(publicKeyHex).slice(0, 16);

  const keyData = { privateKeyHex, publicKeyHex, publicKeyId, generatedAt: new Date().toISOString() };
  fs.writeFileSync(KEY_PATH, JSON.stringify(keyData, null, 2));
  console.log('[MCS] Generated new Ed25519 signing keypair:', publicKeyId);

  return keyData;
}

let _keyPair = null;

function getKeyPair() {
  if (!_keyPair) _keyPair = loadOrGenerateKeyPair();
  return _keyPair;
}

/**
 * Sign arbitrary data with the MCS private key.
 * @param {string} data - string to sign (typically JSON)
 * @returns {string} hex-encoded Ed25519 signature (128 hex chars = 64 bytes)
 */
function signData(data) {
  const { privateKeyHex } = getKeyPair();
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyHex, 'hex'),
    format: 'der',
    type: 'pkcs8',
  });
  const sig = crypto.sign(null, Buffer.from(data, 'utf8'), privateKey);
  return sig.toString('hex');
}

/**
 * Verify an Ed25519 signature against a public key.
 * @param {string} data - original data string
 * @param {string} sigHex - hex-encoded signature
 * @param {string} publicKeyHex - hex-encoded SPKI DER public key
 * @returns {boolean}
 */
function verifySignature(data, sigHex, publicKeyHex) {
  try {
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(publicKeyHex, 'hex'),
      format: 'der',
      type: 'spki',
    });
    return crypto.verify(
      null,
      Buffer.from(data, 'utf8'),
      publicKey,
      Buffer.from(sigHex, 'hex')
    );
  } catch {
    return false;
  }
}

/**
 * Get the public key in hex (SPKI DER) for client-side verification.
 * @returns {{ publicKeyHex: string, publicKeyId: string }}
 */
function getPublicKeyInfo() {
  const { publicKeyHex, publicKeyId } = getKeyPair();
  return { publicKeyHex, publicKeyId };
}

module.exports = {
  sha256hex,
  canonicalize,
  fingerprintContent,
  hashLeaf,
  hashNode,
  buildMerkleTree,
  generateInclusionProof,
  verifyInclusionProof,
  signData,
  verifySignature,
  getPublicKeyInfo,
  loadOrGenerateKeyPair,
};
