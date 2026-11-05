/**
 * Types and interfaces for Argus Panoptes DLP Engine
 */

export enum SensitivitySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum DetectionCategory {
  API_KEY = 'API_KEY',
  JWT_TOKEN = 'JWT_TOKEN',
  PRIVATE_KEY = 'PRIVATE_KEY',
  DATABASE_CREDENTIAL = 'DATABASE_CREDENTIAL',
  HIGH_ENTROPY_SECRET = 'HIGH_ENTROPY_SECRET',
  FINNISH_HETU = 'FINNISH_HETU',
  IBAN = 'IBAN',
  CREDIT_CARD = 'CREDIT_CARD',
  EMAIL = 'EMAIL',
  PHONE_NUMBER = 'PHONE_NUMBER',
  IP_ADDRESS = 'IP_ADDRESS',
  CUSTOM_RULE = 'CUSTOM_RULE'
}

export interface DetectedEntity {
  category: DetectionCategory;
  name: string;
  matchedText: string;
  startIndex: number;
  endIndex: number;
  severity: SensitivitySeverity;
  confidence: number; // 0.0 to 1.0
  redactedPlaceholder: string;
}

export interface DlpScanResult {
  hasViolations: boolean;
  totalViolations: number;
  highestSeverity: SensitivitySeverity | null;
  entities: DetectedEntity[];
  sanitizedText: string;
  scanDurationMs: number;
}

export interface CustomRegexRule {
  name: string;
  pattern: string;
  severity?: SensitivitySeverity;
}

export interface DetectorSettings {
  apiKeysAndSecrets: boolean;
  piiGeneral: boolean;
  finnishHetu: boolean;
  financialIban: boolean;
  highEntropyStrings: boolean;
}

export interface ArgusConfig {
  enabled: boolean;
  mode: 'mask' | 'block' | 'confirm' | 'audit_only';
  proxyPort: number;
  proxyHost: string;
  targetProvider: 'lm-studio' | 'ollama' | 'openai' | 'custom';
  targetBaseUrl: string;
  targetApiKey: string;
  detectors: DetectorSettings;
  agentProtection: {
    blockEnvFiles: boolean;
    inspectToolCalls: boolean;
  };
  customRegexRules: CustomRegexRule[];
  whitelistedPaths: string[];
}

export interface AuditRecord {
  id: string;
  timestamp: string;
  action: 'masked' | 'blocked' | 'confirmed' | 'audited_pass';
  promptSnippet: string;
  entityCount: number;
  categories: DetectionCategory[];
  entityFingerprints: string[]; // SHA-256 hashes of matched text
  targetModel: string;
  durationMs: number;
}

