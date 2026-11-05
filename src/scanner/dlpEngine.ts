import {
  ArgusConfig,
  DetectedEntity,
  DetectionCategory,
  DlpScanResult,
  SensitivitySeverity
} from './types';
import { SECRET_RULES, PII_RULES, validateLuhn } from './regexScanner';
import { findFinnishHetus } from './finnishHetu';
import { findIbans } from './ibanValidator';
import { findHighEntropyTokens } from './entropy';
import { SessionVault } from '../vault/sessionVault';

export class DlpEngine {
  private config: ArgusConfig;
  private vault: SessionVault;

  constructor(config: ArgusConfig, vault?: SessionVault) {
    this.config = config;
    this.vault = vault || new SessionVault();
  }

  public updateConfig(config: ArgusConfig): void {
    this.config = config;
  }

  public getVault(): SessionVault {
    return this.vault;
  }

  /**
   * Scans prompt text for confidential data and leaks according to active settings.
   * @param text Text content to scan
   * @param filePath Optional file path of origin
   * @param ignoreWhitelist If true, bypasses whitelisted paths check (used for manual scans)
   */
  public scan(text: string, filePath?: string, ignoreWhitelist: boolean = false): DlpScanResult {
    const startTime = performance.now();
    const entities: DetectedEntity[] = [];

    // Check if the source file is whitelisted (unless explicit manual scan)
    if (!ignoreWhitelist && filePath && this.isWhitelisted(filePath)) {
      return {
        hasViolations: false,
        totalViolations: 0,
        highestSeverity: null,
        entities: [],
        sanitizedText: text,
        scanDurationMs: Math.round((performance.now() - startTime) * 100) / 100
      };
    }

    if (!this.config.enabled || !text) {
      return {
        hasViolations: false,
        totalViolations: 0,
        highestSeverity: null,
        entities: [],
        sanitizedText: text,
        scanDurationMs: Math.round((performance.now() - startTime) * 100) / 100
      };
    }

    // 1. Secrets & API Keys
    if (this.config.detectors.apiKeysAndSecrets) {
      for (const rule of SECRET_RULES) {
        // Reset regex state
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.pattern.exec(text)) !== null) {
          entities.push({
            category: rule.category,
            name: rule.name,
            matchedText: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            severity: rule.severity,
            confidence: rule.confidence,
            redactedPlaceholder: ''
          });
        }
      }
    }

    // 2. Finnish HETU
    if (this.config.detectors.finnishHetu) {
      const hetus = findFinnishHetus(text);
      for (const item of hetus) {
        entities.push({
          category: DetectionCategory.FINNISH_HETU,
          name: 'Finnish Personal Identity Code (HETU)',
          matchedText: item.hetu,
          startIndex: item.index,
          endIndex: item.index + item.hetu.length,
          severity: SensitivitySeverity.HIGH,
          confidence: 0.99,
          redactedPlaceholder: ''
        });
      }
    }

    // 3. IBAN
    if (this.config.detectors.financialIban) {
      const ibans = findIbans(text);
      for (const item of ibans) {
        entities.push({
          category: DetectionCategory.IBAN,
          name: 'Bank Account Number (IBAN)',
          matchedText: item.iban,
          startIndex: item.index,
          endIndex: item.index + item.iban.length,
          severity: SensitivitySeverity.HIGH,
          confidence: 0.95,
          redactedPlaceholder: ''
        });
      }
    }

    // 4. General PII (Emails, Phones, IP)
    if (this.config.detectors.piiGeneral) {
      for (const rule of PII_RULES) {
        rule.pattern.lastIndex = 0;
        let match: RegExpExecArray | null;
        while ((match = rule.pattern.exec(text)) !== null) {
          // If it's localhost (127.0.0.1 or 0.0.0.0), ignore
          if (rule.category === DetectionCategory.IP_ADDRESS) {
            if (match[0] === '127.0.0.1' || match[0] === '0.0.0.0' || match[0] === '255.255.255.255') {
              continue;
            }
          }

          entities.push({
            category: rule.category,
            name: rule.name,
            matchedText: match[0],
            startIndex: match.index,
            endIndex: match.index + match[0].length,
            severity: rule.severity,
            confidence: rule.confidence,
            redactedPlaceholder: ''
          });
        }
      }

      // Credit card detector with Luhn verification
      const ccRegex = /\b(?:\d{4}[ -]?){3}\d{4}\b|\b\d{13,19}\b/g;
      let ccMatch: RegExpExecArray | null;
      while ((ccMatch = ccRegex.exec(text)) !== null) {
        if (validateLuhn(ccMatch[0])) {
          entities.push({
            category: DetectionCategory.CREDIT_CARD,
            name: 'Payment Card Number (Luhn Validated)',
            matchedText: ccMatch[0],
            startIndex: ccMatch.index,
            endIndex: ccMatch.index + ccMatch[0].length,
            severity: SensitivitySeverity.CRITICAL,
            confidence: 0.95,
            redactedPlaceholder: ''
          });
        }
      }
    }

    // 5. Custom Regex Rules from Settings
    if (this.config.customRegexRules && this.config.customRegexRules.length > 0) {
      for (const custom of this.config.customRegexRules) {
        try {
          const regex = new RegExp(custom.pattern, 'g');
          let customMatch: RegExpExecArray | null;
          while ((customMatch = regex.exec(text)) !== null) {
            entities.push({
              category: DetectionCategory.CUSTOM_RULE,
              name: `Custom Rule: ${custom.name}`,
              matchedText: customMatch[0],
              startIndex: customMatch.index,
              endIndex: customMatch.index + customMatch[0].length,
              severity: custom.severity || SensitivitySeverity.MEDIUM,
              confidence: 0.90,
              redactedPlaceholder: ''
            });
          }
        } catch {
          // Ignore invalid custom regex syntax
        }
      }
    }

    // 6. Shannon Entropy (Unknown high-entropy secrets)
    if (this.config.detectors.highEntropyStrings) {
      const highEntropy = findHighEntropyTokens(text, 20, 4.3);
      for (const item of highEntropy) {
        entities.push({
          category: DetectionCategory.HIGH_ENTROPY_SECRET,
          name: `High-Entropy Secret (Entropy: ${item.entropy})`,
          matchedText: item.token,
          startIndex: item.index,
          endIndex: item.index + item.token.length,
          severity: SensitivitySeverity.MEDIUM,
          confidence: 0.80,
          redactedPlaceholder: ''
        });
      }
    }

    // 7. Deduplicate overlapping matches (prefer longer, higher severity match)
    const dedupedEntities = this.deduplicateEntities(entities);

    // 8. Mask text with vault
    const sanitizedText = this.vault.maskText(text, dedupedEntities);

    const highestSeverity = this.calculateHighestSeverity(dedupedEntities);
    const durationMs = Math.round((performance.now() - startTime) * 100) / 100;

    return {
      hasViolations: dedupedEntities.length > 0,
      totalViolations: dedupedEntities.length,
      highestSeverity,
      entities: dedupedEntities,
      sanitizedText,
      scanDurationMs: durationMs
    };
  }

  private deduplicateEntities(entities: DetectedEntity[]): DetectedEntity[] {
    if (entities.length <= 1) {
      return entities;
    }

    // Sort by startIndex ascending, then length descending
    entities.sort((a, b) => {
      if (a.startIndex !== b.startIndex) {
        return a.startIndex - b.startIndex;
      }
      return (b.endIndex - b.startIndex) - (a.endIndex - a.startIndex);
    });

    const result: DetectedEntity[] = [];
    let lastEnd = -1;

    for (const entity of entities) {
      if (entity.startIndex >= lastEnd) {
        result.push(entity);
        lastEnd = entity.endIndex;
      }
    }

    return result;
  }

  private calculateHighestSeverity(entities: DetectedEntity[]): SensitivitySeverity | null {
    if (entities.length === 0) {
      return null;
    }

    const order = [
      SensitivitySeverity.CRITICAL,
      SensitivitySeverity.HIGH,
      SensitivitySeverity.MEDIUM,
      SensitivitySeverity.LOW
    ];

    for (const sev of order) {
      if (entities.some(e => e.severity === sev)) {
        return sev;
      }
    }

    return SensitivitySeverity.LOW;
  }

  private isWhitelisted(filePath: string): boolean {
    const normalized = filePath.replace(/\\/g, '/');
    for (const pattern of this.config.whitelistedPaths) {
      const cleanPattern = pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*');
      try {
        const regex = new RegExp(cleanPattern, 'i');
        if (regex.test(normalized)) {
          return true;
        }
      } catch {
        // Fallback simple substring
        if (normalized.includes(pattern)) {
          return true;
        }
      }
    }
    return false;
  }
}

