import * as http from 'http';
import * as net from 'net';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { DlpProxyServer } from '../src/proxy/dlpProxy';
import { AuditLogger } from '../src/logger/auditLogger';
import { DlpEngine } from '../src/scanner/dlpEngine';
import { SessionVault } from '../src/vault/sessionVault';
import { ArgusConfig } from '../src/scanner/types';

interface TestResult {
  testId: string;
  passFail: 'PASS' | 'FAIL';
  details: string;
}

const results: TestResult[] = [];

function check(testId: string, condition: boolean, details: string): void {
  const passFail = condition ? 'PASS' : 'FAIL';
  results.push({ testId, passFail, details });
  console.log(`${passFail === 'PASS' ? '✅' : '❌'} ${passFail}: ${testId} — ${details}`);
}

function config(mode: ArgusConfig['mode'], targetBaseUrl: string): ArgusConfig {
  return {
    enabled: true,
    mode,
    proxyPort: 0,
    proxyHost: '127.0.0.1',
    targetProvider: 'custom',
    targetBaseUrl,
    targetApiKey: 'qa-only-key',
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
    customRegexRules: [],
    whitelistedPaths: []
  };
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Mock server did not expose a TCP port'));
        return;
      }
      resolve(address.port);
    });
  });
}

function close(server: http.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
}

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      if (!address || typeof address === 'string') {
        reject(new Error('Port probe did not expose a TCP port'));
        return;
      }
      probe.close(error => error ? reject(error) : resolve(address.port));
    });
  });
}

function request(
  port: number,
  requestPath: string,
  body: string,
  method = 'POST'
): Promise<{ status: number | null; headers: http.IncomingHttpHeaders; body: string; error?: string }> {
  return new Promise(resolve => {
    const req = http.request({
      host: '127.0.0.1',
      port,
      path: requestPath,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, response => {
      let responseBody = '';
      response.setEncoding('utf8');
      response.on('data', chunk => { responseBody += chunk; });
      response.on('end', () => resolve({
        status: response.statusCode ?? null,
        headers: response.headers,
        body: responseBody
      }));
    });
    req.on('error', error => resolve({
      status: null,
      headers: {},
      body: '',
      error: error.message
    }));
    req.end(body);
  });
}

async function runProxyCase(
  mode: ArgusConfig['mode'],
  body: string,
  requestPath = '/v1/chat/completions',
  stream = false,
  method = 'POST'
): Promise<{ response: Awaited<ReturnType<typeof request>>; received: string[] }> {
  const received: string[] = [];
  const mock = http.createServer((req, res) => {
    let requestBody = '';
    req.on('data', chunk => { requestBody += chunk.toString(); });
    req.on('end', () => {
      received.push(requestBody);
      if ((req.url || '').includes('/error')) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'synthetic upstream error' } }));
        return;
      }

      const tokenMatch = requestBody.match(/<ARGUS_[^>]+>/);
      const token = tokenMatch ? tokenMatch[0] : 'clean';
      if (stream) {
        const content = JSON.stringify({ choices: [{ delta: { content: `Echo ${token}` } }] });
        const splitAt = content.indexOf(token) + Math.max(1, Math.floor(token.length / 2));
        res.writeHead(200, {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          Connection: 'keep-alive'
        });
        res.write(`data: ${content.slice(0, splitAt)}`);
        res.end(`${content.slice(splitAt)}\n\ndata: [DONE]\n\n`);
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ choices: [{ message: { content: `Echo ${token}` } }] }));
    });
  });
  const mockPort = await listen(mock);
  const storageDir = fsTempDir();
  const cfg = config(mode, `http://127.0.0.1:${mockPort}/v1`);
  cfg.proxyPort = await getFreePort();
  const vault = new SessionVault();
  const engine = new DlpEngine(cfg, vault);
  const proxy = new DlpProxyServer(cfg, engine, new AuditLogger(storageDir));
  const proxyPort = await proxy.start();
  const response = await request(proxyPort, requestPath, body, method);
  await proxy.stop();
  await close(mock);
  return { response, received };
}

function fsTempDir(): string {
  return path.join(os.tmpdir(), `argus-regression-${process.pid}-${Date.now()}`);
}

function runScannerRegression(): void {
  const cfg = config('mask', 'http://127.0.0.1:1/v1');
  const engine = new DlpEngine(cfg, new SessionVault());
  const iban = 'FI2112345600000785';
  const twoIbans = engine.scan(`Use ${iban} and ${iban} for duplicate coverage.`);
  check(
    'BUG-002-context-and-multiple-iban',
    twoIbans.entities.length === 2 && twoIbans.entities.every(entity => entity.category === 'IBAN') &&
      twoIbans.entities.every(entity => entity.matchedText === iban),
    `categories=${twoIbans.entities.map(entity => entity.category).join(',')}; matches=${twoIbans.entities.map(entity => entity.matchedText).join('|')}`
  );

  const beforeAs = engine.scan(`The synthetic account is ${iban} as a fixture.`);
  check(
    'BUG-002-iban-before-as',
    beforeAs.entities.length === 1 && beforeAs.entities[0].category === 'IBAN' && beforeAs.entities[0].matchedText === iban,
    `categories=${beforeAs.entities.map(entity => entity.category).join(',')}; matches=${beforeAs.entities.map(entity => entity.matchedText).join('|')}`
  );

  const invalidHetu = engine.scan('Invalid HETU 010101/001R.');
  check(
    'BUG-003-no-phone-inside-invalid-hetu',
    invalidHetu.entities.every(entity => entity.category !== 'PHONE_NUMBER'),
    `categories=${invalidHetu.entities.map(entity => entity.category).join(',')}; matches=${invalidHetu.entities.map(entity => entity.matchedText).join('|')}`
  );

  const invalidCard = engine.scan('Invalid card 4532 0151 1283 0367.');
  check(
    'BUG-003-no-phone-inside-invalid-card',
    invalidCard.entities.every(entity => entity.category !== 'PHONE_NUMBER'),
    `categories=${invalidCard.entities.map(entity => entity.category).join(',')}; matches=${invalidCard.entities.map(entity => entity.matchedText).join('|')}`
  );

  const phone = engine.scan('Call +358 40 123 4567.');
  check(
    'BUG-003-ordinary-phone-regression',
    phone.entities.length === 1 && phone.entities[0].category === 'PHONE_NUMBER' && phone.entities[0].matchedText === '+358 40 123 4567',
    `categories=${phone.entities.map(entity => entity.category).join(',')}; matches=${phone.entities.map(entity => entity.matchedText).join('|')}`
  );
}

async function runVaultRegression(): Promise<void> {
  const engine = new DlpEngine(config('mask', 'http://127.0.0.1:1/v1'), new SessionVault());
  const source = 'Email qa@example.test and HETU 131052-308T.';
  const scan = engine.scan(source);
  const restored = engine.getVault().unmaskText(scan.sanitizedText);
  check('V001-roundtrip-multiple', restored === source, restored);

  const repeatedSource = 'qa@example.test / qa@example.test';
  const repeated = engine.scan(repeatedSource);
  const repeatedTokens = repeated.entities.map(entity => entity.redactedPlaceholder);
  check('V002-repeated-value-reuse', repeatedTokens.length === 2 && repeatedTokens[0] === repeatedTokens[1] && engine.getVault().unmaskText(repeated.sanitizedText) === repeatedSource, JSON.stringify({ repeatedTokens, restored: engine.getVault().unmaskText(repeated.sanitizedText) }));

  const unknown = engine.getVault().unmaskText('<ARGUS_UNKNOWN_999>');
  check('V003-unknown-token', unknown === '<ARGUS_UNKNOWN_999>', unknown);

  const damaged = engine.getVault().unmaskText('<ARGUS_EMAIL_');
  check('V004-damaged-token', damaged === '<ARGUS_EMAIL_', damaged);

  const vault = new SessionVault();
  const emailToken = vault.getOrCreateToken('same synthetic value', 'EMAIL');
  const apiToken = vault.getOrCreateToken('same synthetic value', 'API_KEY');
  check('BUG-010-category-aware-mapping', emailToken !== apiToken, `${emailToken} vs ${apiToken}`);
  check('BUG-010-opaque-token', !/^<ARGUS_EMAIL_\d+>$/.test(emailToken), emailToken);

  const scopedVault = new SessionVault();
  const firstToken = scopedVault.getOrCreateToken('qa@example.test', 'EMAIL');
  const beginRequest = (scopedVault as unknown as { beginRequest?: () => void }).beginRequest;
  if (beginRequest) {
    beginRequest.call(scopedVault);
  }
  const unrelated = scopedVault.unmaskText(`unrelated response ${firstToken}`);
  check('BUG-009-cross-request-isolation', unrelated === `unrelated response ${firstToken}`, unrelated);
}

async function runProxyRegression(): Promise<void> {
  const secret = 'qa@example.test';
  const health = await runProxyCase('mask', '', '/health', false, 'GET');
  check('P000-health-endpoint', health.response.status === 200 && health.received.length === 0, JSON.stringify(health.response));

  const simple = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'user', content: `Email ${secret}` }] }));
  check('P001-mask-email', simple.response.status === 200 && simple.received.length === 1 && !simple.received[0].includes(secret), JSON.stringify(simple));
  check('P001-mask-email-response', simple.response.body.includes(secret), simple.response.body);

  const blocked = await runProxyCase('block', JSON.stringify({ messages: [{ role: 'user', content: secret }] }));
  check('P002-block-email', blocked.response.status === 403 && blocked.received.length === 0, JSON.stringify(blocked.response));

  const confirmed = await runProxyCase('confirm', JSON.stringify({ messages: [{ role: 'user', content: secret }] }));
  check('P003-confirm-fails-closed', confirmed.response.status === 428 && confirmed.received.length === 0, JSON.stringify(confirmed.response));

  const auditOnly = await runProxyCase('audit_only', JSON.stringify({ messages: [{ role: 'user', content: secret }] }));
  check('P004-audit-only-forwards-by-policy', auditOnly.response.status === 200 && auditOnly.received.length === 1 && auditOnly.received[0].includes(secret), JSON.stringify(auditOnly));

  const malformedBaseline = await runProxyCase('mask', `{"messages":[{"role":"user","content":"${secret}"`);
  check('P005-malformed-json-blocked', malformedBaseline.response.status === 400 && malformedBaseline.received.length === 0, JSON.stringify(malformedBaseline.response));

  const multimodal = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'user', content: [{ type: 'text', text: secret }] }] }));
  check('P006-multimodal-scanned', multimodal.response.status === 200 && multimodal.received.length === 1 && !multimodal.received[0].includes(secret), JSON.stringify(multimodal));

  const toolCall = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'assistant', tool_calls: [{ function: { arguments: JSON.stringify({ email: secret }) } }] }] }));
  check('P007-tool-call-scanned', toolCall.response.status === 200 && toolCall.received.length === 1 && !toolCall.received[0].includes(secret), JSON.stringify(toolCall));

  const upstream = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'user', content: 'safe synthetic text' }] }), '/v1/chat/completions/error');
  check('P008-upstream-error-preserved', upstream.response.status === 500 && !upstream.response.error, JSON.stringify(upstream.response));

  const stream = await runProxyCase('mask', JSON.stringify({ stream: true, messages: [{ role: 'user', content: secret }] }), '/v1/chat/completions', true);
  check('P009-sse-split-placeholder-restored', stream.response.status === 200 && stream.response.body.includes(secret) && !stream.response.body.includes('<ARGUS_'), JSON.stringify(stream.response));

  const topLevelKey = await runProxyCase('mask', JSON.stringify({ [secret]: 'synthetic value', messages: [{ role: 'user', content: 'safe synthetic text' }] }));
  check('J001-top-level-key-blocked', topLevelKey.response.status === 400 && topLevelKey.received.length === 0, JSON.stringify(topLevelKey.response));

  const nestedKey = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'user', content: { [secret]: 'synthetic value' } }] }));
  check('J002-nested-key-blocked', nestedKey.response.status === 400 && nestedKey.received.length === 0, JSON.stringify(nestedKey.response));

  const arrayKey = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'user', content: [{ type: 'text', [secret]: 'synthetic value' }] }] }));
  check('J003-array-key-blocked', arrayKey.response.status === 400 && arrayKey.received.length === 0, JSON.stringify(arrayKey.response));

  const safeKey = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'user', content: 'safe synthetic text' }] }));
  check('J004-safe-openai-keys-allowed', safeKey.response.status === 200 && safeKey.received.length === 1 && !safeKey.received[0].includes(secret), JSON.stringify(safeKey.response));

  const valueSecret = await runProxyCase('mask', JSON.stringify({ messages: [{ role: 'user', content: secret }] }));
  check('J005-value-secret-still-masked', valueSecret.response.status === 200 && valueSecret.received.length === 1 && !valueSecret.received[0].includes(secret), JSON.stringify(valueSecret));

  const unsupportedRoot = await runProxyCase('mask', JSON.stringify([{ messages: [{ role: 'user', content: secret }] }]));
  check('J006-unsupported-root-fails-closed', unsupportedRoot.response.status === 400 && unsupportedRoot.received.length === 0, JSON.stringify(unsupportedRoot.response));

  const nestedBody = JSON.stringify({
    model: 'qa',
    messages: [{ role: 'user', content: [{ type: 'text', text: `Email ${secret}` }] }],
    tool_calls: [{ function: { arguments: JSON.stringify({ email: secret }) } }]
  });
  const masked = await runProxyCase('mask', nestedBody);
  check('BUG-007-nested-content-masking', masked.received.length === 1 && !masked.received[0].includes(secret), masked.received[0] || 'Mock received no request');
  check('BUG-005-normal-response-transport', masked.response.status === 200 && !masked.response.error, JSON.stringify(masked.response));
  check('BUG-007-response-restoration', masked.response.body.includes(secret), masked.response.body);

  const malformed = await runProxyCase('mask', `{"messages":[{"role":"user","content":"${secret}"`);
  check('BUG-007-malformed-json-blocked', malformed.response.status === 400 && malformed.received.length === 0, JSON.stringify(malformed.response));

  check('BUG-006-confirm-fails-closed', confirmed.response.status === 428 && confirmed.received.length === 0, JSON.stringify(confirmed.response));
  check('BUG-008-sse-placeholder-restored', stream.response.status === 200 && stream.response.body.includes(secret) && !stream.response.body.includes('<ARGUS_'), JSON.stringify(stream.response));
  check('BUG-005-upstream-status-preserved', upstream.response.status === 500 && !upstream.response.error, JSON.stringify(upstream.response));
}

async function main(): Promise<void> {
  runScannerRegression();
  await runVaultRegression();
  await runProxyRegression();

  const pass = results.filter(result => result.passFail === 'PASS').length;
  const fail = results.length - pass;
  const outputPath = process.env.ARGUS_REGRESSION_OUTPUT;
  if (outputPath) {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify({ total: results.length, pass, fail, results }, null, 2) + '\n', 'utf8');
  }
  console.log(`\nRegression summary: ${pass} PASS, ${fail} FAIL, ${results.length} total`);
  if (fail > 0) {
    process.exitCode = 1;
  }
}

void main().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
