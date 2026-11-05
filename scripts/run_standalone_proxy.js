const { DlpEngine } = require('../dist/scanner/dlpEngine');
const { SessionVault } = require('../dist/vault/sessionVault');
const { AuditLogger } = require('../dist/logger/auditLogger');
const { DlpProxyServer } = require('../dist/proxy/dlpProxy');

const config = {
  enabled: true,
  mode: process.env.ARGUS_MODE || 'mask', // 'mask' | 'block' | 'audit_only'
  proxyPort: parseInt(process.env.ARGUS_PORT || '8080', 10),
  proxyHost: '127.0.0.1',
  targetProvider: 'lm-studio',
  targetBaseUrl: process.env.ARGUS_TARGET || 'http://127.0.0.1:1234/v1',
  targetApiKey: 'lm-studio-local',
  detectors: {
    apiKeysAndSecrets: true,
    piiGeneral: true,
    finnishHetu: true,
    financialIban: true,
    highEntropyStrings: true,
  },
  agentProtection: {
    blockEnvFiles: true,
    inspectToolCalls: true,
  },
  customRegexRules: [],
  whitelistedPaths: ['**/test/**'],
};

const vault = new SessionVault();
const engine = new DlpEngine(config, vault);
const logger = new AuditLogger();

const proxy = new DlpProxyServer(config, engine, logger);

proxy
  .start()
  .then((port) => {
    console.log(`\n======================================================`);
    console.log(`🛡️  Argus Panoptes DLP Standalone Proxy is RUNNING!`);
    console.log(`======================================================`);
    console.log(`📍 Listening on:      http://127.0.0.1:${port}/v1`);
    console.log(`🎯 Forwarding to:      ${config.targetBaseUrl}`);
    console.log(`⚙️  Active Policy:     ${config.mode.toUpperCase()}`);
    console.log(`🔍 Direct scan API:   POST http://127.0.0.1:${port}/api/scan`);
    console.log(`💓 Health check:      GET http://127.0.0.1:${port}/health`);
    console.log(`======================================================\n`);
    console.log(`To test in another terminal, run:`);
    console.log(
      `curl -X POST http://127.0.0.1:${port}/api/scan -H "Content-Type: application/json" -d "{\\"text\\":\\"Here is key sk-proj-12345678901234567890123456789012 and HETU 131052-308T\\"}"\n`,
    );
  })
  .catch((err) => {
    console.error(`❌ Failed to start proxy:`, err.message);
    process.exit(1);
  });
