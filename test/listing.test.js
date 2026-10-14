const test = require('node:test');
const assert = require('node:assert/strict');
const { nextListingStatus } = require('../src/mcpsecure/listing');

test('listing state follows the verdict (spec §9.1, decision D5)', () => {
  assert.equal(nextListingStatus('pending', 'PASS'), 'approved');
  assert.equal(nextListingStatus('pending', 'REVIEW'), 'in_review');
  assert.equal(nextListingStatus('pending', 'FAIL'), 'rejected');
  // an update to a listed server that lands in REVIEW keeps the listing
  assert.equal(nextListingStatus('approved', 'REVIEW'), 'approved');
  assert.equal(nextListingStatus('legacy', 'REVIEW'), 'legacy');
  // a listed server whose update FAILs is suspended (rug pull)
  assert.equal(nextListingStatus('approved', 'FAIL'), 'suspended');
});
