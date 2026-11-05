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
exports.getArgusConfig = getArgusConfig;
const vscode = __importStar(require("vscode"));
const types_1 = require("./scanner/types");
function getArgusConfig() {
    const cfg = vscode.workspace.getConfiguration('argus');
    return {
        enabled: cfg.get('enabled', true),
        mode: cfg.get('mode', 'mask'),
        proxyPort: cfg.get('proxy.port', 8765),
        proxyHost: cfg.get('proxy.host', '127.0.0.1'),
        targetProvider: cfg.get('target.provider', 'lm-studio'),
        targetBaseUrl: cfg.get('target.baseUrl', 'http://127.0.0.1:1234/v1'),
        targetApiKey: cfg.get('target.apiKey', 'lm-studio'),
        detectors: {
            apiKeysAndSecrets: cfg.get('detectors.apiKeysAndSecrets', true),
            piiGeneral: cfg.get('detectors.piiGeneral', true),
            finnishHetu: cfg.get('detectors.finnishHetu', true),
            financialIban: cfg.get('detectors.financialIban', true),
            highEntropyStrings: cfg.get('detectors.highEntropyStrings', true)
        },
        agentProtection: {
            blockEnvFiles: cfg.get('agentProtection.blockEnvFiles', true),
            inspectToolCalls: cfg.get('agentProtection.inspectToolCalls', true)
        },
        customRegexRules: (cfg.get('customRegexRules', [])).map(r => ({
            name: r.name,
            pattern: r.pattern,
            severity: r.severity || types_1.SensitivitySeverity.MEDIUM
        })),
        whitelistedPaths: cfg.get('whitelistedPaths', [
            '**/test/**',
            '**/tests/**',
            '**/.env.example',
            '**/fixtures/**'
        ])
    };
}
//# sourceMappingURL=config.js.map