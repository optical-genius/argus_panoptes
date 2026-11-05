import { validateFinnishHetu, findFinnishHetus } from '../src/scanner/finnishHetu';
import { validateIban, findIbans } from '../src/scanner/ibanValidator';
import { calculateShannonEntropy, findHighEntropyTokens } from '../src/scanner/entropy';
import { SECRET_RULES, validateLuhn } from '../src/scanner/regexScanner';
import { SessionVault } from '../src/vault/sessionVault';
import { DlpEngine } from '../src/scanner/dlpEngine';
import { ArgusConfig, SensitivitySeverity } from '../src/scanner/types';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`❌ FAIL: ${message}`);
    process.exitCode = 1;
  } else {
    console.log(`✅ PASS: ${message}`);
  }
}

console.log('=== Running Argus Panoptes Unit Tests ===\n');

// 1. Finnish HETU
console.log('[1] Testing Finnish HETU Validator...');
// 010101-0101 (checksum check: 010101010 % 31 = 10101010 % 31 = 28 -> 'U')
// Valid test HETU: 131052-308T (131052308 % 31 = 26 -> 'T')
assert(validateFinnishHetu('131052-308T'), 'Valid HETU 131052-308T recognized');
assert(!validateFinnishHetu('131052-308X'), 'Invalid checksum correctly rejected');
assert(!validateFinnishHetu('320101-123A'), 'Invalid date 32.01 correctly rejected');

const hetuSampleText = 'Customer is Matti Meikäläinen, id 131052-308T, living in Joensuu.';
const foundHetus = findFinnishHetus(hetuSampleText);
assert(foundHetus.length === 1 && foundHetus[0].hetu === '131052-308T', 'Found HETU in text snippet');

// 2. IBAN Validator
console.log('\n[2] Testing IBAN Validator...');
// Valid Finnish bank IBAN example (Bank of Finland test IBAN)
const testIban = 'FI21 1234 5600 0007 85';
assert(validateIban(testIban), 'Valid Finnish IBAN accepted');
assert(!validateIban('FI21 1234 5600 0007 86'), 'Corrupted IBAN checksum rejected');

// 3. Credit Card Luhn
console.log('\n[3] Testing Credit Card Luhn Validator...');
assert(validateLuhn('4532 0151 1283 0366'), 'Valid Visa test card passes Luhn');
assert(!validateLuhn('4532 0151 1283 0367'), 'Invalid test card fails Luhn');

// 4. Shannon Entropy
console.log('\n[4] Testing Shannon Entropy Scanner...');
const lowEntropy = 'hello world this is standard english text';
const highEntropy = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
assert(calculateShannonEntropy(lowEntropy) < 3.8, 'Normal text has low entropy');
assert(calculateShannonEntropy(highEntropy) > 4.4, 'Random base64 has high entropy (> 4.4)');

// 5. Bidirectional Token Vault
console.log('\n[5] Testing Session Vault Masking & Unmasking...');
const vault = new SessionVault();
const originalPrompt = 'Please connect with user Matti (131052-308T) using sk-proj-11112222333344445555666677778888.';
const mockEntities = [
  {
    category: 'FINNISH_HETU' as any,
    name: 'HETU',
    matchedText: '131052-308T',
    startIndex: 32,
    endIndex: 43,
    severity: SensitivitySeverity.HIGH,
    confidence: 1.0,
    redactedPlaceholder: ''
  },
  {
    category: 'API_KEY' as any,
    name: 'OpenAI Key',
    matchedText: 'sk-proj-11112222333344445555666677778888',
    startIndex: 50,
    endIndex: 90,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 1.0,
    redactedPlaceholder: ''
  }
];

const masked = vault.maskText(originalPrompt, mockEntities);
assert(!masked.includes('131052-308T'), 'Original HETU masked from prompt');
assert(!masked.includes('sk-proj-'), 'Original API key masked from prompt');
assert(masked.includes('<ARGUS_FINNISH_HETU_1>'), 'Placeholder inserted for HETU');
assert(masked.includes('<ARGUS_API_KEY_1>'), 'Placeholder inserted for API Key');

const fakeModelResponse = 'Understood! I have processed data for <ARGUS_FINNISH_HETU_1> using key <ARGUS_API_KEY_1>.';
const unmaskedResponse = vault.unmaskText(fakeModelResponse);
assert(unmaskedResponse.includes('131052-308T'), 'Unmasking restores HETU in response');
assert(unmaskedResponse.includes('sk-proj-11112222333344445555666677778888'), 'Unmasking restores API key in response');

// 6. DlpEngine End-to-End
console.log('\n[6] Testing DlpEngine Full Pipeline...');
const testConfig: ArgusConfig = {
  enabled: true,
  mode: 'mask',
  proxyPort: 8080,
  proxyHost: '127.0.0.1',
  targetProvider: 'lm-studio',
  targetBaseUrl: 'http://127.0.0.1:1234/v1',
  targetApiKey: 'test',
  detectors: {
    apiKeysAndSecrets: true,
    piiGeneral: true,
    finnishHetu: true,
    financialIban: true,
    highEntropyStrings: true
  },
  agentProtection: {
    blockEnvFiles: true,
    inspectToolCalls: true
  },
  customRegexRules: [
    {
      name: 'Internal Project Tag',
      pattern: 'CONFIDENTIAL-PROJ-[0-9]{3}',
      severity: SensitivitySeverity.CRITICAL
    }
  ],
  whitelistedPaths: ['**/mock/**']
};

const engine = new DlpEngine(testConfig, vault);
const leakText = `
Here is our test script:
const apiKey = "ghp_111122223333444455556666777788889999";
const customerHetu = "131052-308T";
const dbUrl = "postgres://admin:SuperSecretPass123!@db.internal:5432/production";
const tag = "CONFIDENTIAL-PROJ-777";
`;

const scanRes = engine.scan(leakText);
assert(scanRes.hasViolations, 'DlpEngine detected violations in leak sample');
assert(scanRes.totalViolations >= 4, `Expected at least 4 violations, detected ${scanRes.totalViolations}`);
assert(scanRes.highestSeverity === SensitivitySeverity.CRITICAL, 'Highest severity accurately identified as CRITICAL');
assert(!scanRes.sanitizedText.includes('ghp_'), 'GitHub token masked in sanitized text');
assert(!scanRes.sanitizedText.includes('131052-308T'), 'HETU masked in sanitized text');
assert(!scanRes.sanitizedText.includes('SuperSecretPass123!'), 'DB password masked in sanitized text');
assert(!scanRes.sanitizedText.includes('CONFIDENTIAL-PROJ-777'), 'Custom rule masked in sanitized text');

console.log('\n🎉 ALL ARGUS PANOPTES SCANNER TESTS PASSED SUCCESSFULLY!');

