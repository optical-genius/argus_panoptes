import assert from 'assert';
import { getVisualPromptSnippet } from '../src/views/tokenDisplay';

const fullEmailToken = `<ARGUS_EMAIL_${'a'.repeat(32)}>`;

const fullSnippet = `MASKED ${fullEmailToken}`;
assert.equal(getVisualPromptSnippet(fullSnippet), 'MASKED <ARGUS_EMAIL_1>');

const sourceWithLongPrefix = `${'x'.repeat(50)}${fullEmailToken}`;
const auditSnippetWithTruncatedToken = `${sourceWithLongPrefix.slice(0, 80)}...`;
assert.match(auditSnippetWithTruncatedToken, /<ARGUS_EMAIL_[0-9a-f]+\.\.\.$/);
assert.equal(
  getVisualPromptSnippet(auditSnippetWithTruncatedToken),
  `${'x'.repeat(50)}<ARGUS_EMAIL_1>...`
);

assert.equal(
  getVisualPromptSnippet(`<ARGUS_EMAIL_${'b'.repeat(32)}...`),
  '<ARGUS_EMAIL_1>...'
);

console.log('✅ PASS: complete and truncated Argus tokens use short visual aliases');
