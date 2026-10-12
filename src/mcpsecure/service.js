/**
 * MCP Secure — Core Service Layer
 * =================================
 * Orchestrates scan → attest → log → anchor pipeline.
 * Used by the API routes and the seed script.
 */

const { v4: uuidv4 } = require('uuid');
const mcsCrypto = require('./crypto');
const engine = require('./engine');
const store = require('./store');

// How many attestations before auto-anchoring (configurable)
const ANCHOR_EVERY_N = 3;

// ─── Build and sign an attestation ────────────────────────────────────────────

function buildAttestation(scanRecord) {
  const { publicKeyId } = mcsCrypto.getPublicKeyInfo();
  const recordStr = JSON.stringify(scanRecord);
  const attestationId = mcsCrypto.sha256hex(recordStr);
  const signature = mcsCrypto.signData(recordStr);
  const createdAt = new Date().toISOString();

  return {
    scanRecord,
    attestationId,
    signature,
    publicKeyId,
    createdAt,
  };
}

// ─── Anchor logic ─────────────────────────────────────────────────────────────

function simulateAnchor() {
  const leaves = store.getLogLeaves();
  if (leaves.length === 0) return null;

  const leafData = leaves.map(l => l.attestationId);
  const { root } = mcsCrypto.buildMerkleTree(leafData);

  // Simulated chain: monotonically increasing block number.
  //
  // Every value below is DERIVED, never random. The previous implementation
  // used Math.random() for the block advance and Date.now() inside the tx
  // hash, which made the anchor receipt the one artifact in the system that
  // could not be reproduced from its inputs. Determinism is the project's
  // headline property, so the mock has to honour it too — otherwise the
  // honest answer to "is all of it deterministic?" is "no, except the bit we
  // forgot about".
  //
  // Production note: a real Sepolia transaction is NOT deterministic in this
  // way — block number and tx hash come from the network, and re-anchoring
  // the same root would yield a different hash. What carries over is the
  // receipt SHAPE and the fact that only the Merkle root is ever published.
  const lastBlock = store.getLatestBlockNumber();
  const advance = (parseInt(root.slice(0, 8), 16) % 12) + 1; // 1..12, from the root
  const blockNumber = lastBlock + advance;
  const txHash = '0x' + mcsCrypto.sha256hex(`anchor:${root}:${blockNumber}`).slice(0, 64);

  // Wall-clock, deliberately: this mirrors a real block timestamp, which is an
  // observation rather than a derivation. It is not hashed into anything.
  const blockTimestamp = new Date().toISOString();

  const receipt = {
    rootHash: root,
    txHash,
    blockNumber,
    blockTimestamp,
    network: 'SIMULATED_CHAIN',
    logSizeAtAnchor: leaves.length,
  };

  store.saveAnchor(receipt);
  return receipt;
}

// ─── Full pipeline: scan → attest → log → maybe anchor ───────────────────────

/**
 * Run the complete scan pipeline for a server.
 * @param {object} serverContent - { serverId, name, description, long_description, github_url, tools }
 * @param {number} [version]
 * @param {boolean} [isExternal=false]
 * @returns {{ scanRecord, attestation, logIndex, anchored }}
 */
async function runFullPipeline(serverContent, version, isExternal = false, onStage = null) {
  const stage = async (name, status, detail) => {
    // Reserved keys go LAST so a detail field can never clobber them.
    if (onStage) await onStage({ ...(detail || {}), stage: name, status });
  };

  // 1. Detection pipeline runs first (Analyzers + Policy Engine)
  const scanRecord = await engine.simulateScan(serverContent, version || 1, onStage);

  // 2. Check if detection and security checks are CLEAR
  if (scanRecord.verdict === 'PASS') {
    // Only once detection is clear are hashes generated and stored in blockchain
    await stage('attest', 'start');
    const attestedAt = Date.now();
    const attestation = buildAttestation(scanRecord);

    // Persist verified record
    store.saveScanRecord(scanRecord, attestation);
    await stage('attest', 'done', {
      ms: Date.now() - attestedAt,
      attestationId: attestation.attestationId,
    });

    // Push to transparency log (Merkle leaf)
    await stage('log', 'start');
    const loggedAt = Date.now();
    const leafData = attestation.attestationId;
    const leafHash = mcsCrypto.hashLeaf(leafData);
    const logIndex = store.appendLogLeaf(attestation.attestationId, leafHash);
    await stage('log', 'done', { ms: Date.now() - loggedAt, logIndex, leafHash });

    // Anchor to blockchain
    await stage('anchor', 'start');
    const anchoredAt = Date.now();
    let anchored = simulateAnchor();
    await stage('anchor', 'done', {
      ms: Date.now() - anchoredAt,
      blockNumber: anchored && anchored.blockNumber,
    });

    // Update watcher row (only for marketplace servers, not preview)
    if (!isExternal) {
      store.upsertWatcherRow({
        serverId: serverContent.serverId,
        watchedRef: 'main',
        lastSeenSha: scanRecord.snapshot.commitSha,
        lastFingerprint: scanRecord.snapshot.contentFingerprint,
        lastVerdict: scanRecord.verdict,
        lastCheckedAt: new Date().toISOString(),
        status: 'up_to_date',
      });
    }

    return {
      scanRecord,
      attestation,
      logIndex,
      anchored,
      blockchainStored: true,
      hashesGenerated: true,
    };
  } else {
    // Before detection is clear: hashes are NOT generated and NOT stored in blockchain!
    const rejectionAttestation = {
      scanRecord,
      attestationId: 'blocked:' + uuidv4(),
      signature: null,
      publicKeyId: null,
      createdAt: new Date().toISOString(),
      status: scanRecord.verdict === 'FAIL' ? 'REJECTED' : 'PENDING_REVIEW',
      blockchainStored: false,
    };

    // Save scan record locally for audit, but NEVER push to mcs_log_leaves or blockchain
    store.saveScanRecord(scanRecord, rejectionAttestation);
    await stage('blocked', 'done', {
      verdict: scanRecord.verdict,
      attestationStatus: rejectionAttestation.status,
      reason: scanRecord.snapshot.blockedReason || null,
    });

    return {
      scanRecord,
      attestation: rejectionAttestation,
      logIndex: null,
      anchored: null,
      blockchainStored: false,
      hashesGenerated: false,
      blockedReason: scanRecord.verdict === 'FAIL'
        ? 'Security threats detected during pipeline. Hashes withheld; storage in blockchain blocked.'
        : 'Suspicious patterns flagged for review. Hashes withheld; awaiting manual review before blockchain storage.',
    };
  }
}

// ─── Get signed tree head ─────────────────────────────────────────────────────

function getSignedTreeHead() {
  const leaves = store.getLogLeaves();
  const leafData = leaves.map(l => l.attestationId);
  const { root } = mcsCrypto.buildMerkleTree(leafData);

  const sth = {
    rootHash: root,
    size: leaves.length,
    timestamp: new Date().toISOString(),
  };

  const { publicKeyId } = mcsCrypto.getPublicKeyInfo();
  const signature = mcsCrypto.signData(JSON.stringify(sth));

  return { ...sth, signature, publicKeyId };
}

// ─── Client-verify a server by fingerprint ────────────────────────────────────

function lookupByFingerprint(fingerprint) {
  return store.getScanRecordByFingerprint(fingerprint);
}

// ─── Inclusion proof for a leaf ───────────────────────────────────────────────

function getInclusionProof(leafIndex) {
  const leaves = store.getLogLeaves();
  const leafData = leaves.map(l => l.attestationId);

  if (leafIndex < 0 || leafIndex >= leaves.length) {
    throw new Error(`Leaf index ${leafIndex} out of range`);
  }

  return mcsCrypto.generateInclusionProof(leafData, leafIndex);
}

// ─── Public key export ────────────────────────────────────────────────────────

function getPublicKeyExport() {
  return mcsCrypto.getPublicKeyInfo();
}

// ─── Upgrade stub (commented reference) ──────────────────────────────────────
// /**
//  * anchorToSepolia(rootHash)
//  * Production upgrade path: replace simulateAnchor() with this function.
//  *
//  * const { ethers } = require('ethers');
//  * async function anchorToSepolia(rootHash) {
//  *   const provider = new ethers.JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
//  *   const wallet = new ethers.Wallet(process.env.ANCHOR_PRIVATE_KEY, provider);
//  *   const tx = await wallet.sendTransaction({
//  *     to: process.env.ANCHOR_CONTRACT_ADDRESS,
//  *     data: ethers.hexlify(ethers.toUtf8Bytes('MCS:' + rootHash)),
//  *   });
//  *   await tx.wait();
//  *   return { txHash: tx.hash, blockNumber: tx.blockNumber };
//  * }
//  */

module.exports = {
  runFullPipeline,
  buildAttestation,
  simulateAnchor,
  getSignedTreeHead,
  lookupByFingerprint,
  getInclusionProof,
  getPublicKeyExport,
};
