"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.SessionVault = void 0;
const crypto = __importStar(require("crypto"));
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
    /**
     * Starts a new request scope and discards mappings from the previous one.
     * Proxy requests use a separate vault instance as an additional isolation
     * boundary; this method is useful for callers that reuse a vault explicitly.
     */
    beginRequest() {
        this.clear();
    }
    /**
     * Clears all session entries.
     */
    clear() {
        this.tokenToOriginal.clear();
        this.originalToToken.clear();
    }
    /**
     * Generates or retrieves an existing placeholder token for a sensitive value.
     */
    getOrCreateToken(originalValue, category) {
        const mappingKey = `${category}\u0000${originalValue}`;
        if (this.originalToToken.has(mappingKey)) {
            return this.originalToToken.get(mappingKey);
        }
        let placeholder;
        do {
            const opaqueId = crypto.randomBytes(16).toString('hex');
            placeholder = `<ARGUS_${category}_${opaqueId}>`;
        } while (this.tokenToOriginal.has(placeholder));
        const entry = {
            placeholder,
            originalValue,
            category,
            timestamp: Date.now()
        };
        this.tokenToOriginal.set(placeholder, entry);
        this.originalToToken.set(mappingKey, placeholder);
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