"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionVault = void 0;
/**
 * Bidirectional Token Vault:
 * 1. Anonymizes sensitive entities in the prompt by replacing them with placeholders.
 * 2. Unmasks / re-identifies the placeholders when the LLM returns its response.
 *
 * This ensures the remote/local LLM never sees real secrets or PII,
 * while the developer in the IDE receives a coherent and complete answer.
 */
class SessionVault {
    tokenToOriginal = new Map();
    originalToToken = new Map();
    categoryCounters = new Map();
    /**
     * Clears all session entries.
     */
    clear() {
        this.tokenToOriginal.clear();
        this.originalToToken.clear();
        this.categoryCounters.clear();
    }
    /**
     * Generates or retrieves an existing placeholder token for a sensitive value.
     */
    getOrCreateToken(originalValue, category) {
        if (this.originalToToken.has(originalValue)) {
            return this.originalToToken.get(originalValue);
        }
        const currentCount = (this.categoryCounters.get(category) || 0) + 1;
        this.categoryCounters.set(category, currentCount);
        const placeholder = `<ARGUS_${category}_${currentCount}>`;
        const entry = {
            placeholder,
            originalValue,
            category,
            timestamp: Date.now()
        };
        this.tokenToOriginal.set(placeholder, entry);
        this.originalToToken.set(originalValue, placeholder);
        return placeholder;
    }
    /**
     * Replaces all detected entities in the text with vault placeholders.
     * Processes entities from right to left (descending startIndex) to preserve text offsets.
     */
    maskText(text, entities) {
        if (!entities || entities.length === 0) {
            return text;
        }
        // Sort descending by startIndex
        const sorted = [...entities].sort((a, b) => b.startIndex - a.startIndex);
        let result = text;
        for (const entity of sorted) {
            const placeholder = this.getOrCreateToken(entity.matchedText, entity.category);
            entity.redactedPlaceholder = placeholder;
            result =
                result.slice(0, entity.startIndex) +
                    placeholder +
                    result.slice(entity.endIndex);
        }
        return result;
    }
    /**
     * Replaces placeholders back with their original sensitive values in the LLM's response.
     */
    unmaskText(text) {
        if (!text || this.tokenToOriginal.size === 0) {
            return text;
        }
        let unmasked = text;
        for (const [placeholder, entry] of this.tokenToOriginal.entries()) {
            // Replace all occurrences of placeholder
            unmasked = unmasked.split(placeholder).join(entry.originalValue);
        }
        return unmasked;
    }
    /**
     * Returns current active vault entries count.
     */
    getEntryCount() {
        return this.tokenToOriginal.size;
    }
}
exports.SessionVault = SessionVault;
//# sourceMappingURL=sessionVault.js.map