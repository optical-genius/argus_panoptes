import * as vscode from 'vscode';
import { ArgusConfig, SensitivitySeverity } from './scanner/types';

export function getArgusConfig(): ArgusConfig {
  const cfg = vscode.workspace.getConfiguration('argus');

  return {
    enabled: cfg.get<boolean>('enabled', true),
    mode: cfg.get<'mask' | 'block' | 'confirm' | 'audit_only'>('mode', 'mask'),
    proxyPort: cfg.get<number>('proxy.port', 8765),
    proxyHost: cfg.get<string>('proxy.host', '127.0.0.1'),
    targetProvider: cfg.get<'lm-studio' | 'ollama' | 'openai' | 'custom'>('target.provider', 'lm-studio'),
    targetBaseUrl: cfg.get<string>('target.baseUrl', 'http://127.0.0.1:1234/v1'),
    targetApiKey: cfg.get<string>('target.apiKey', 'lm-studio'),
    detectors: {
      apiKeysAndSecrets: cfg.get<boolean>('detectors.apiKeysAndSecrets', true),
      piiGeneral: cfg.get<boolean>('detectors.piiGeneral', true),
      finnishHetu: cfg.get<boolean>('detectors.finnishHetu', true),
      financialIban: cfg.get<boolean>('detectors.financialIban', true),
      highEntropyStrings: cfg.get<boolean>('detectors.highEntropyStrings', true)
    },
    agentProtection: {
      blockEnvFiles: cfg.get<boolean>('agentProtection.blockEnvFiles', true),
      inspectToolCalls: cfg.get<boolean>('agentProtection.inspectToolCalls', true)
    },
    customRegexRules: (cfg.get<Array<{ name: string; pattern: string; severity?: string }>>('customRegexRules', [])).map(r => ({
      name: r.name,
      pattern: r.pattern,
      severity: (r.severity as SensitivitySeverity) || SensitivitySeverity.MEDIUM
    })),
    whitelistedPaths: cfg.get<string[]>('whitelistedPaths', [
      '**/test/**',
      '**/tests/**',
      '**/.env.example',
      '**/fixtures/**'
    ])
  };
}

