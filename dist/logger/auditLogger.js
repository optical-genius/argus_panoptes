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
exports.AuditLogger = void 0;
const crypto = __importStar(require("crypto"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
class AuditLogger {
    static fingerprintSalt = crypto.randomBytes(32);
    logFilePath;
    recentRecords = [];
    maxRecentRecords = 100;
    onRecordAddedListeners = [];
    constructor(storageDir) {
        const dir = storageDir || path.join(process.cwd(), '.argus');
        try {
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true });
            }
        }
        catch {
            // Fallback
        }
        this.logFilePath = path.join(dir, 'audit.jsonl');
        this.loadRecentRecords();
    }
    onRecordAdded(listener) {
        this.onRecordAddedListeners.push(listener);
    }
    /**
     * Creates a process-local HMAC fingerprint for privacy-preserving auditing.
     * The random salt prevents offline dictionary matching from the log alone.
     */
    static hashEntity(value) {
        return crypto.createHmac('sha256', AuditLogger.fingerprintSalt).update(value).digest('hex').slice(0, 16);
    }
    /**
     * Logs a DLP scanning event.
     */
    logEvent(action, scanResult, rawPrompt, targetModel) {
        // Take a short safe snippet of the prompt (first 80 chars, without secrets)
        const safeSnippet = scanResult.sanitizedText.slice(0, 80).replace(/[\r\n]+/g, ' ') + '...';
        const fingerprints = scanResult.entities.map(e => `${e.category}:${AuditLogger.hashEntity(e.matchedText)}`);
        const record = {
            id: crypto.randomUUID(),
            timestamp: new Date().toISOString(),
            action,
            promptSnippet: safeSnippet,
            entityCount: scanResult.totalViolations,
            categories: Array.from(new Set(scanResult.entities.map(e => e.category))),
            entityFingerprints: fingerprints,
            targetModel,
            durationMs: scanResult.scanDurationMs
        };
        this.recentRecords.unshift(record);
        if (this.recentRecords.length > this.maxRecentRecords) {
            this.recentRecords.pop();
        }
        this.appendToFile(record);
        for (const listener of this.onRecordAddedListeners) {
            try {
                listener(record);
            }
            catch {
                // Ignore listener errors
            }
        }
        return record;
    }
    getRecentRecords() {
        return [...this.recentRecords];
    }
    getStats() {
        const leaksByCategory = {};
        let totalLeaks = 0;
        for (const record of this.recentRecords) {
            totalLeaks += record.entityCount;
            for (const cat of record.categories) {
                leaksByCategory[cat] = (leaksByCategory[cat] || 0) + 1;
            }
        }
        return {
            totalScans: this.recentRecords.length,
            totalLeaksPrevented: totalLeaks,
            leaksByCategory
        };
    }
    appendToFile(record) {
        try {
            const line = JSON.stringify(record) + '\n';
            fs.appendFileSync(this.logFilePath, line, 'utf8');
        }
        catch {
            // In-memory fallback if file write fails
        }
    }
    loadRecentRecords() {
        try {
            if (fs.existsSync(this.logFilePath)) {
                const content = fs.readFileSync(this.logFilePath, 'utf8');
                const lines = content.trim().split('\n').filter(l => l.trim().length > 0);
                const records = [];
                // Read last 100 lines
                const slice = lines.slice(-this.maxRecentRecords);
                for (const line of slice) {
                    try {
                        records.unshift(JSON.parse(line));
                    }
                    catch {
                        // Ignore corrupted lines
                    }
                }
                this.recentRecords = records;
            }
        }
        catch {
            this.recentRecords = [];
        }
    }
}
exports.AuditLogger = AuditLogger;
//# sourceMappingURL=auditLogger.js.map