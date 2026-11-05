import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

export interface DetectedAgentInfo {
  id: string;
  name: string;
  version: string;
  isAiAgent: boolean;
  status: 'guarded' | 'unprotected' | 'built_in_cloud';
  details: string;
}

export interface SystemSecurityAudit {
  globalProxyConfigured: boolean;
  globalProxyUrl: string | null;
  aiIgnoreActive: boolean;
  detectedAgents: DetectedAgentInfo[];
  recommendations: string[];
}

const KNOWN_AI_EXTENSIONS: Record<string, string> = {
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

export class AgentAuditor {
  /**
   * Performs a comprehensive security audit of active AI agents,
   * proxy routing, and workspace file ignore shields.
   */
  public static auditEnvironment(argusPort: number): SystemSecurityAudit {
    const recommendations: string[] = [];
    const detectedAgents: DetectedAgentInfo[] = [];

    // 1. Check Global IDE HTTP Proxy Setting
    const httpConfig = vscode.workspace.getConfiguration('http');
    const proxyUrl = httpConfig.get<string>('proxy') || null;
    const isGlobalProxyArgus = proxyUrl !== null && proxyUrl.includes(`:${argusPort}`);

    if (!isGlobalProxyArgus) {
      recommendations.push(
        `Global IDE proxy is not routed to Argus (port :${argusPort}). Cloud agents can bypass local proxy.`
      );
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
      recommendations.push(
        'Workspace lacks .aiignore file. Autonomous agents can read secret files (.env, keys) directly.'
      );
    }

    // 3. Scan installed extensions for AI assistants
    const installed = vscode.extensions.all;
    for (const ext of installed) {
      const id = ext.id.toLowerCase();
      for (const [knownId, friendlyName] of Object.entries(KNOWN_AI_EXTENSIONS)) {
        if (id.includes(knownId.toLowerCase())) {
          let status: 'guarded' | 'unprotected' | 'built_in_cloud' = 'unprotected';
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
  public static createAiIgnoreFile(): boolean {
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
  public static async configureGlobalProxy(port: number): Promise<void> {
    const httpConfig = vscode.workspace.getConfiguration('http');
    await httpConfig.update('proxy', `http://127.0.0.1:${port}`, vscode.ConfigurationTarget.Global);
    await httpConfig.update('proxySupport', 'override', vscode.ConfigurationTarget.Global);
  }
}

