/**
 * Submission gate API (spec §9.2), mounted at /api/v1.
 */

const express = require('express');
const router = express.Router();
const subs = require('../mcpsecure/submissions');
const store = require('../mcpsecure/store');
const { oneRow } = require('../db');
const { requireAuth, requireAdmin } = require('../middleware/auth');

function fail(res, e) {
  if (!e.status) console.error('[MCS /api/v1]', e);
  res.status(e.status || 500).json({ error: e.message });
}

function isAdmin(userId) {
  const u = oneRow(`SELECT role FROM users WHERE id = ?`, [userId]);
  return !!u && u.role === 'admin';
}

function canSee(req, sub) {
  return sub && (sub.submitterId === req.user.id || isAdmin(req.user.id));
}

// Submit a server for scanning. The listing stays hidden until the verdict allows it.
router.post('/submissions', requireAuth, (req, res) => {
  try {
    const { submission, server } = subs.createSubmission(req.user, req.body || {});
    res.status(202).json({
      submission,
      server: { id: server.id, slug: server.slug, name: server.name, listing_status: server.listing_status },
      events_url: `/api/v1/submissions/${submission.id}/events`,
    });
  } catch (e) { fail(res, e); }
});

router.get('/submissions', requireAuth, (req, res) => {
  try { res.json(subs.listForUser(req.user.id)); } catch (e) { fail(res, e); }
});

router.get('/submissions/:id', requireAuth, (req, res) => {
  try {
    const sub = subs.getSubmission(req.params.id);
    if (!canSee(req, sub)) return res.status(404).json({ error: 'Submission not found' });
    const server = oneRow(`SELECT id, slug, name, listing_status, security_status FROM servers WHERE id = ?`, [sub.serverId]);
    const scan = sub.scanRecordId ? store.getScanRecordById(sub.scanRecordId) : null;
    res.json({ submission: sub, server, scan, decisions: subs.decisionsFor(sub.id) });
  } catch (e) { fail(res, e); }
});

// Live progress (Server-Sent Events). Replays everything emitted so far.
router.get('/submissions/:id/events', requireAuth, (req, res) => {
  const sub = subs.getSubmission(req.params.id);
  if (!canSee(req, sub)) return res.status(404).json({ error: 'Submission not found' });

  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  if (typeof res.flushHeaders === 'function') res.flushHeaders();

  const send = ({ event, data }) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  send({ event: 'begin', data: { submissionId: sub.id, state: sub.state } });

  // Already finished before the client attached (e.g. after a restart): send the stored result.
  const finished = ['approved', 'in_review', 'rejected', 'failed'].includes(sub.state);
  const unsubscribe = subs.subscribe(sub.id, (e) => {
    send(e);
    if (e.event === 'result' || e.event === 'error') res.end();
  });
  if (finished && sub.scanRecordId) {
    const record = store.getScanRecordById(sub.scanRecordId);
    if (record) send({ event: 'result', data: { submissionId: sub.id, scanRecord: record.attestation.scanRecord || record, attestation: record.attestation, replay: true } });
    res.end();
  } else if (finished && sub.state === 'failed') {
    send({ event: 'error', data: { error: sub.error } });
    res.end();
  }
  req.on('close', unsubscribe);
});

router.get('/review-queue', requireAdmin, (req, res) => {
  try { res.json(subs.reviewQueue()); } catch (e) { fail(res, e); }
});

router.post('/submissions/:id/decision', requireAdmin, (req, res) => {
  try {
    const { decision, note } = req.body || {};
    res.json({ submission: subs.decide(req.params.id, req.user, decision, note), decisions: subs.decisionsFor(req.params.id) });
  } catch (e) { fail(res, e); }
});

module.exports = router;
