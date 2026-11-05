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
exports.AgentAuditor = void 0;
const vscode = __importStar(require("vscode"));
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const KNOWN_AI_EXTENSIONS = {
    'github.copilot': 'GitHub Copilot',
    'github.copilot-chat': 'GitHub Copilot Chat',
    'continue.continue': 'Continue.dev AI Assistant',
    'rooveterinaryinc.roo-cline': 'Roo Code (Cline)',
    'saoudrizwan.claude-dev': 'Claude Dev / Cline',
    'codeium.codeium': 'Codeium AI',
    'tabnine.tabnine-vscode': 'Tabnine AI',
    'amazonwebservices.amazon-q-vscode': 'Amazon Q Developer',
    'google.gemini': 'Google Gemini Code Assist',
    'google.antigravity': 'Antigravity Native Agent'
};
class AgentAuditor {
    /**
     * Performs a comprehensive security audit of active AI agents,
     * proxy routing, and workspace file ignore shields.
     */
    static auditEnvironment(argusPort) {
        const recommendations = [];
        const detectedAgents = [];
        // 1. Check Global IDE HTTP Proxy Setting
        const httpConfig = vscode.workspace.getConfiguration('http');
        const proxyUrl = httpConfig.get('proxy') || null;
        const isGlobalProxyArgus = proxyUrl !== null && proxyUrl.includes(`:${argusPort}`);
        if (!isGlobalProxyArgus) {
            recommendations.push(`Global IDE proxy is not routed to Argus (port :${argusPort}). Cloud agents can bypass local proxy.`);
        }
        // 2. Check for .aiignore / .antigravityignore in workspace
        let aiIgnoreActive = false;
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (workspaceFolders && workspaceFolders.length > 0) {
            const root = workspaceFolders[0].uri.fsPath;
            const ignoreFiles = ['.aiignore', '.antigravityignore', '.cursorignore'];
            for (const f of ignoreFiles) {
                if (fs.existsSync(path.join(root, f))) {
                    aiIgnoreActive = true;
                    break;
                }
            }
        }
        if (!aiIgnoreActive) {
            recommendations.push('Workspace lacks .aiignore file. Autonomous agents can read secret files (.env, keys) directly.');
        }
        // 3. Scan installed extensions for AI assistants
        const installed = vscode.extensions.all;
        for (const ext of installed) {
            const id = ext.id.toLowerCase();
            for (const [knownId, friendlyName] of Object.entries(KNOWN_AI_EXTENSIONS)) {
                if (id.includes(knownId.toLowerCase())) {
                    let status = 'unprotected';
                    let details = 'Routes traffic directly to vendor cloud.';
                    if (isGlobalProxyArgus) {
                        status = 'guarded';
                        details = `Protected: all outbound traffic routes through Argus (: ${argusPort}).`;
                    }
                    detectedAgents.push({
                        id: ext.id,
                        name: friendlyName,
                        version: ext.packageJSON.version || '1.0.0',
                        isAiAgent: true,
                        status,
                        details
                    });
                }
            }
        }
        // Check for native Antigravity IDE built-in chat agent
        const isAntigravity = vscode.env.appName.toLowerCase().includes('antigravity');
        if (isAntigravity) {
            detectedAgents.unshift({
                id: 'antigravity.native.chat',
                name: 'Antigravity Native Agent (MAI-Code / Gemini Cloud)',
                version: vscode.version,
                isAiAgent: true,
                status: isGlobalProxyArgus ? 'guarded' : 'built_in_cloud',
                details: isGlobalProxyArgus
                    ? 'Guarded via global IDE proxy.'
                    : 'Direct cloud agent: reads files into cloud context without local proxy unless .aiignore is used.'
            });
        }
        return {
            globalProxyConfigured: isGlobalProxyArgus,
            globalProxyUrl: proxyUrl,
            aiIgnoreActive,
            detectedAgents,
            recommendations
        };
    }
    /**
     * Creates or updates a standard .aiignore file protecting secrets from being read by agents.
     */
    static createAiIgnoreFile() {
        const workspaceFolders = vscode.workspace.workspaceFolders;
        if (!workspaceFolders || workspaceFolders.length === 0) {
            return false;
        }
        const root = workspaceFolders[0].uri.fsPath;
        const content = `# Argus Panoptes AI Shield: Prevent AI agents from reading sensitive files
.env
.env.*
*.pem
*.key
id_rsa
id_ed25519
*secret*
*credential*
*.p12
*.kdbx
config_secret.py
`;
        const targetPaths = [
            path.join(root, '.aiignore'),
            path.join(root, '.antigravityignore'),
            path.join(root, '.cursorignore')
        ];
        for (const p of targetPaths) {
            fs.writeFileSync(p, content, 'utf8');
        }
        return true;
    }
    /**
     * Configures VS Code / Antigravity IDE global proxy to route through Argus.
     */
    static async configureGlobalProxy(port) {
        const httpConfig = vscode.workspace.getConfiguration('http');
        await httpConfig.update('proxy', `http://127.0.0.1:${port}`, vscode.ConfigurationTarget.Global);
        await httpConfig.update('proxySupport', 'override', vscode.ConfigurationTarget.Global);
    }
}
exports.AgentAuditor = AgentAuditor;
//# sourceMappingURL=agentAuditor.js.map