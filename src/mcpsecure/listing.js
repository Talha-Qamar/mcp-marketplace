/**
 * MCP Secure — listing state after a verdict (spec §9.1, decision D5)
 * ====================================================================
 * A server is visible in the catalog only while listing_status is
 * 'approved' (or 'legacy': seeded catalog rows that predate the gate).
 *
 *   PASS    → approved
 *   REVIEW  → in_review, unless the server is already listed: then it stays
 *             listed (pinned to its last approved scan) while the update waits
 *   FAIL    → rejected, or suspended if it was listed (rug pull)
 */

const { runSql } = require('../db');

const LISTED = new Set(['approved', 'legacy']);
const SECURITY_STATUS = { PASS: 'verified', REVIEW: 'unverified', FAIL: 'malicious' };

function nextListingStatus(current, verdict) {
  const listed = LISTED.has(current);
  if (verdict === 'PASS') return 'approved';
  if (verdict === 'REVIEW') return listed ? current : 'in_review';
  if (verdict === 'FAIL') return listed ? 'suspended' : 'rejected';
  return current || 'pending';
}

function applyVerdict(server, verdict) {
  const listing = nextListingStatus(server.listing_status, verdict);
  runSql(`UPDATE servers SET security_status = ?, listing_status = ?, updated_at = ? WHERE id = ?`,
    [SECURITY_STATUS[verdict] || 'unverified', listing, new Date().toISOString(), server.id]);
  return listing;
}

module.exports = { nextListingStatus, applyVerdict, LISTED, SECURITY_STATUS };
