/**
 * MCP Secure — Database Store
 * ============================
 * Thin wrapper over the marketplace db layer (src/db.js).
 * All MCS tables are prefixed with mcs_ to avoid conflicts.
 *
 * Persistence: data survives server restarts via database/marketplace.db
 */

const { allRows, oneRow, runSql } = require('../db');
const { v4: uuidv4 } = require('uuid');

// ─── Scan Records ─────────────────────────────────────────────────────────────

function saveScanRecord(scanRecord, attestation) {
  const id = attestation.attestationId;
  const now = new Date().toISOString();

  runSql(`
    INSERT OR REPLACE INTO mcs_scan_records
      (id, server_id, version, snapshot_json, analyzers_json, verdict, policy_version, ruleset_hash, model_hashes_json, attestation_json, record_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    id,
    scanRecord.snapshot.serverId,
    scanRecord.snapshot.version,
    JSON.stringify(scanRecord.snapshot),
    JSON.stringify(scanRecord.analyzers),
    scanRecord.verdict,
    scanRecord.policyVersion,
    scanRecord.rulesetHash,
    JSON.stringify(scanRecord.modelVersionHashes),
    JSON.stringify(attestation),
    JSON.stringify(scanRecord),
    attestation.createdAt || now,
  ]);

  return id;
}

function getScanRecords(serverId) {
  const rows = allRows(`
    SELECT * FROM mcs_scan_records
    WHERE server_id = ?
    ORDER BY version DESC
  `, [serverId]);
  return rows.map(parseScanRow);
}

function getScanRecordById(id) {
  const row = oneRow(`SELECT * FROM mcs_scan_records WHERE id = ?`, [id]);
  return row ? parseScanRow(row) : null;
}

function getScanRecordByFingerprint(fingerprint) {
  // Find the latest scan record whose snapshot has a matching contentFingerprint
  const rows = allRows(`SELECT * FROM mcs_scan_records ORDER BY version DESC`);
  for (const row of rows) {
    const snap = JSON.parse(row.snapshot_json || '{}');
    if (snap.contentFingerprint === fingerprint) return parseScanRow(row);
  }
  return null;
}

function getAllScanRecords(limit = 100) {
  const rows = allRows(`
    SELECT * FROM mcs_scan_records ORDER BY created_at DESC LIMIT ?
  `, [limit]);
  return rows.map(parseScanRow);
}

function markScanSuperseded(id) {
  runSql(`UPDATE mcs_scan_records SET superseded = 1 WHERE id = ?`, [id]);
}

function parseScanRow(row) {
  // record_json holds the full ScanRecord (contract results, policy reasons,
  // ingestion summary). Rows written before it existed have none of those.
  const record = row.record_json ? JSON.parse(row.record_json) : {};
  return {
    subject: record.subject || null,
    ingest: record.ingest || null,
    results: record.results || [],
    policy: record.policy || null,
    triage: record.triage || null,
    id: row.id,
    serverId: row.server_id,
    version: row.version,
    snapshot: JSON.parse(row.snapshot_json || '{}'),
    analyzers: JSON.parse(row.analyzers_json || '[]'),
    verdict: row.verdict,
    policyVersion: row.policy_version,
    rulesetHash: row.ruleset_hash,
    modelVersionHashes: JSON.parse(row.model_hashes_json || '{}'),
    attestation: JSON.parse(row.attestation_json || '{}'),
    superseded: row.superseded === 1,
    isExternal: row.is_external === 1,
    createdAt: row.created_at,
  };
}

// ─── Transparency Log ─────────────────────────────────────────────────────────

function appendLogLeaf(attestationId, leafHash) {
  const maxIdx = oneRow(`SELECT MAX(leaf_index) as m FROM mcs_log_leaves`);
  const index = maxIdx && maxIdx.m !== null ? maxIdx.m + 1 : 0;
  const now = new Date().toISOString();

  runSql(`
    INSERT INTO mcs_log_leaves (leaf_index, attestation_id, leaf_hash, created_at)
    VALUES (?, ?, ?, ?)
  `, [index, attestationId, leafHash, now]);

  return index;
}

function getLogLeaves() {
  return allRows(`SELECT * FROM mcs_log_leaves ORDER BY leaf_index ASC`).map(r => ({
    index: r.leaf_index,
    attestationId: r.attestation_id,
    leafHash: r.leaf_hash,
    createdAt: r.created_at,
  }));
}

// ─── Anchor Receipts ──────────────────────────────────────────────────────────

function saveAnchor(anchor) {
  const id = uuidv4();
  const now = new Date().toISOString();
  runSql(`
    INSERT INTO mcs_anchor_receipts (id, root_hash, tx_hash, block_number, block_timestamp, network, log_size_at_anchor, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `, [id, anchor.rootHash, anchor.txHash, anchor.blockNumber, anchor.blockTimestamp, anchor.network || 'SIMULATED_CHAIN', anchor.logSizeAtAnchor || 0, now]);
  return id;
}

function getAnchors() {
  return allRows(`SELECT * FROM mcs_anchor_receipts ORDER BY block_number DESC`).map(r => ({
    id: r.id,
    rootHash: r.root_hash,
    txHash: r.tx_hash,
    blockNumber: r.block_number,
    blockTimestamp: r.block_timestamp,
    network: r.network,
    logSizeAtAnchor: r.log_size_at_anchor,
    createdAt: r.created_at,
  }));
}

function getLatestBlockNumber() {
  const row = oneRow(`SELECT MAX(block_number) as m FROM mcs_anchor_receipts`);
  return row && row.m !== null ? row.m : 19_850_000; // Start at a realistic Ethereum-like block number
}

// ─── Watcher Rows ─────────────────────────────────────────────────────────────

function getWatcherRows() {
  return allRows(`SELECT * FROM mcs_watcher_rows ORDER BY updated_at DESC`).map(parseWatcherRow);
}

function getWatcherRow(serverId) {
  const row = oneRow(`SELECT * FROM mcs_watcher_rows WHERE server_id = ?`, [serverId]);
  return row ? parseWatcherRow(row) : null;
}

function upsertWatcherRow(data) {
  const existing = getWatcherRow(data.serverId);
  const now = new Date().toISOString();

  if (existing) {
    runSql(`
      UPDATE mcs_watcher_rows SET
        watched_ref = ?, last_seen_sha = ?, last_fingerprint = ?,
        last_verdict = ?, last_checked_at = ?, status = ?, updated_at = ?
      WHERE server_id = ?
    `, [
      data.watchedRef, data.lastSeenSha, data.lastFingerprint,
      data.lastVerdict, data.lastCheckedAt, data.status, now,
      data.serverId,
    ]);
  } else {
    runSql(`
      INSERT INTO mcs_watcher_rows (server_id, watched_ref, last_seen_sha, last_fingerprint, last_verdict, last_checked_at, status, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      data.serverId, data.watchedRef, data.lastSeenSha, data.lastFingerprint,
      data.lastVerdict, data.lastCheckedAt, data.status, now,
    ]);
  }
}

function parseWatcherRow(row) {
  return {
    serverId: row.server_id,
    watchedRef: row.watched_ref,
    lastSeenSha: row.last_seen_sha,
    lastFingerprint: row.last_fingerprint,
    lastVerdict: row.last_verdict,
    lastCheckedAt: row.last_checked_at,
    status: row.status,
    updatedAt: row.updated_at,
  };
}

// ─── External Verification Requests ───────────────────────────────────────────

function saveExternalRequest(req) {
  const id = uuidv4();
  const now = new Date().toISOString();
  runSql(`
    INSERT INTO mcs_external_requests (id, requester_name, candidate_ref, verdict, attestation_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [id, req.requesterName, req.candidateRef, req.verdict, req.attestationId, now]);
  return id;
}

function getExternalRequests(limit = 50) {
  return allRows(`SELECT * FROM mcs_external_requests ORDER BY created_at DESC LIMIT ?`, [limit]).map(r => ({
    id: r.id,
    requesterName: r.requester_name,
    candidateRef: r.candidate_ref,
    verdict: r.verdict,
    attestationId: r.attestation_id,
    createdAt: r.created_at,
  }));
}

module.exports = {
  saveScanRecord,
  getScanRecords,
  getScanRecordById,
  getScanRecordByFingerprint,
  getAllScanRecords,
  markScanSuperseded,
  appendLogLeaf,
  getLogLeaves,
  saveAnchor,
  getAnchors,
  getLatestBlockNumber,
  getWatcherRows,
  getWatcherRow,
  upsertWatcherRow,
  saveExternalRequest,
  getExternalRequests,
};
