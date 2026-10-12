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

  // Simulated chain: monotonically increasing block number
  const lastBlock = store.getLatestBlockNumber();
  const blockNumber = lastBlock + Math.floor(Math.random() * 12) + 1;
  const txHash = '0x' + mcsCrypto.sha256hex(`anchor:${root}:${blockNumber}:${Date.now()}`).slice(0, 64);
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
async function runFullPipeline(serverContent, version, isExternal = false) {
  // 1. Detection pipeline runs first (Analyzers + Policy Engine)
  const scanRecord = await engine.runScan(serverContent, version || 1);

  // 2. Check if detection and security checks are CLEAR
  if (scanRecord.verdict === 'PASS') {
    // Only once detection is clear are hashes generated and stored in blockchain
    const attestation = buildAttestation(scanRecord);

    // Persist verified record
    store.saveScanRecord(scanRecord, attestation);

    // Push to transparency log (Merkle leaf)
    const leafData = attestation.attestationId;
    const leafHash = mcsCrypto.hashLeaf(leafData);
    const logIndex = store.appendLogLeaf(attestation.attestationId, leafHash);

    // Anchor to blockchain
    let anchored = simulateAnchor();

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
