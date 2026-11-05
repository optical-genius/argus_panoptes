"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DlpEngine = void 0;
const types_1 = require("./types");
const regexScanner_1 = require("./regexScanner");
const finnishHetu_1 = require("./finnishHetu");
const ibanValidator_1 = require("./ibanValidator");
const entropy_1 = require("./entropy");
const sessionVault_1 = require("../vault/sessionVault");
class DlpEngine {
    config;
    vault;
    constructor(config, vault) {
        this.config = config;
        this.vault = vault || new sessionVault_1.SessionVault();
    }
    updateConfig(config) {
        this.config = config;
    }
    getVault() {
        return this.vault;
    }
    /**
     * Scans prompt text for confidential data and leaks according to active settings.
     * @param text Text content to scan
     * @param filePath Optional file path of origin
     * @param ignoreWhitelist If true, bypasses whitelisted paths check (used for manual scans)
     */
    scan(text, filePath, ignoreWhitelist = false) {
        const startTime = performance.now();
        const entities = [];
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
            for (const rule of regexScanner_1.SECRET_RULES) {
                // Reset regex state
                rule.pattern.lastIndex = 0;
                let match;
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
            const hetus = (0, finnishHetu_1.findFinnishHetus)(text);
            for (const item of hetus) {
                entities.push({
                    category: types_1.DetectionCategory.FINNISH_HETU,
                    name: 'Finnish Personal Identity Code (HETU)',
                    matchedText: item.hetu,
                    startIndex: item.index,
                    endIndex: item.index + item.hetu.length,
                    severity: types_1.SensitivitySeverity.HIGH,
                    confidence: 0.99,
                    redactedPlaceholder: ''
                });
            }
        }
        // 3. IBAN
        if (this.config.detectors.financialIban) {
            const ibans = (0, ibanValidator_1.findIbans)(text);
            for (const item of ibans) {
                entities.push({
                    category: types_1.DetectionCategory.IBAN,
                    name: 'Bank Account Number (IBAN)',
                    matchedText: item.iban,
                    startIndex: item.index,
                    endIndex: item.index + item.iban.length,
                    severity: types_1.SensitivitySeverity.HIGH,
                    confidence: 0.95,
                    redactedPlaceholder: ''
                });
            }
        }
        // 4. General PII (Emails, Phones, IP)
        if (this.config.detectors.piiGeneral) {
            for (const rule of regexScanner_1.PII_RULES) {
                rule.pattern.lastIndex = 0;
                let match;
                while ((match = rule.pattern.exec(text)) !== null) {
                    // If it's localhost (127.0.0.1 or 0.0.0.0), ignore
                    if (rule.category === types_1.DetectionCategory.IP_ADDRESS) {
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
            let ccMatch;
            while ((ccMatch = ccRegex.exec(text)) !== null) {
                if ((0, regexScanner_1.validateLuhn)(ccMatch[0])) {
                    entities.push({
                        category: types_1.DetectionCategory.CREDIT_CARD,
                        name: 'Payment Card Number (Luhn Validated)',
                        matchedText: ccMatch[0],
                        startIndex: ccMatch.index,
                        endIndex: ccMatch.index + ccMatch[0].length,
                        severity: types_1.SensitivitySeverity.CRITICAL,
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
                    let customMatch;
                    while ((customMatch = regex.exec(text)) !== null) {
                        entities.push({
                            category: types_1.DetectionCategory.CUSTOM_RULE,
                            name: `Custom Rule: ${custom.name}`,
                            matchedText: customMatch[0],
                            startIndex: customMatch.index,
                            endIndex: customMatch.index + customMatch[0].length,
                            severity: custom.severity || types_1.SensitivitySeverity.MEDIUM,
                            confidence: 0.90,
                            redactedPlaceholder: ''
                        });
                    }
                }
                catch {
                    // Ignore invalid custom regex syntax
                }
            }
        }
        // 6. Shannon Entropy (Unknown high-entropy secrets)
        if (this.config.detectors.highEntropyStrings) {
            const highEntropy = (0, entropy_1.findHighEntropyTokens)(text, 20, 4.3);
            for (const item of highEntropy) {
                entities.push({
                    category: types_1.DetectionCategory.HIGH_ENTROPY_SECRET,
                    name: `High-Entropy Secret (Entropy: ${item.entropy})`,
                    matchedText: item.token,
                    startIndex: item.index,
                    endIndex: item.index + item.token.length,
                    severity: types_1.SensitivitySeverity.MEDIUM,
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
    deduplicateEntities(entities) {
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
        const result = [];
        let lastEnd = -1;
        for (const entity of entities) {
            if (entity.startIndex >= lastEnd) {
                result.push(entity);
                lastEnd = entity.endIndex;
            }
        }
        return result;
    }
    calculateHighestSeverity(entities) {
        if (entities.length === 0) {
            return null;
        }
        const order = [
            types_1.SensitivitySeverity.CRITICAL,
            types_1.SensitivitySeverity.HIGH,
            types_1.SensitivitySeverity.MEDIUM,
            types_1.SensitivitySeverity.LOW
        ];
        for (const sev of order) {
            if (entities.some(e => e.severity === sev)) {
                return sev;
            }
        }
        return types_1.SensitivitySeverity.LOW;
    }
    isWhitelisted(filePath) {
        const normalized = filePath.replace(/\\/g, '/');
        for (const pattern of this.config.whitelistedPaths) {
            const cleanPattern = pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*');
            try {
                const regex = new RegExp(cleanPattern, 'i');
                if (regex.test(normalized)) {
                    return true;
                }
            }
            catch {
                // Fallback simple substring
                if (normalized.includes(pattern)) {
                    return true;
                }
            }
        }
        return false;
    }
}
exports.DlpEngine = DlpEngine;
//# sourceMappingURL=dlpEngine.js.map