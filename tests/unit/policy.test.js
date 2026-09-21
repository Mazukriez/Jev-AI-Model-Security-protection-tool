const test = require('node:test');
const assert = require('node:assert/strict');

function decide(findings) {
  if (findings.some(f => f.severity === 'critical')) return 'BLOCK';
  if (findings.some(f => f.severity === 'high' || f.severity === 'medium')) return 'REVIEW';
  return 'ALLOW';
}

test('critical finding blocks', () => assert.equal(decide([{severity:'critical'}]), 'BLOCK'));
test('high finding requires review', () => assert.equal(decide([{severity:'high'}]), 'REVIEW'));
test('low-only findings allow', () => assert.equal(decide([{severity:'low'}]), 'ALLOW'));
