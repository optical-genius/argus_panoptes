import * as vscode from 'vscode';
import { ArgusConfig } from '../scanner/types';
import { DlpEngine } from '../scanner/dlpEngine';
import { AuditLogger } from '../logger/auditLogger';
import { DlpProxyServer } from '../proxy/dlpProxy';
import { AgentAuditor } from '../audit/agentAuditor';

export class ArgusDashboardViewProvider implements vscode.WebviewViewProvider {
  public static readonly viewType = 'argus.dashboardView';
  private _view?: vscode.WebviewView;

  constructor(
    private readonly _extensionUri: vscode.Uri,
    private config: ArgusConfig,
    private dlpEngine: DlpEngine,
    private auditLogger: AuditLogger,
    private proxyServer: DlpProxyServer
  ) {
    this.auditLogger.onRecordAdded(() => {
      this.refresh();
    });
  }

  public updateConfig(config: ArgusConfig): void {
    this.config = config;
    this.refresh();
  }

  public resolveWebviewView(
    webviewView: vscode.WebviewView,
    _context: vscode.WebviewViewResolveContext,
    _token: vscode.CancellationToken
  ) {
    this._view = webviewView;

    webviewView.webview.options = {
      enableScripts: true,
      localResourceRoots: [this._extensionUri]
    };

    webviewView.webview.html = this.getHtmlForWebview(webviewView.webview);

    webviewView.webview.onDidReceiveMessage(async (data) => {
      switch (data.type) {
        case 'testScan': {
          const result = this.dlpEngine.scan(data.text);
          webviewView.webview.postMessage({
            type: 'scanResult',
            result
          });
          break;
        }
        case 'toggleProxy': {
          if (this.proxyServer.getIsRunning()) {
            await this.proxyServer.stop();
          } else {
            await this.proxyServer.start();
          }
          this.refresh();
          break;
        }
        case 'openSettings': {
          vscode.commands.executeCommand('workbench.action.openSettings', 'argus');
          break;
        }
        case 'switchMode': {
          const newMode = data.mode;
          await vscode.workspace.getConfiguration('argus').update('mode', newMode, vscode.ConfigurationTarget.Global);
          vscode.window.showInformationMessage(`🛡️ Argus DLP Mode switched to: ${newMode.toUpperCase()}`);
          break;
        }
        case 'createAiIgnore': {
          const success = AgentAuditor.createAiIgnoreFile();
          if (success) {
            vscode.window.showInformationMessage('🛡️ Argus: Created .aiignore shield in workspace root! AI agents will now ignore secret files.');
          } else {
            vscode.window.showWarningMessage('Please open a workspace folder first to create .aiignore.');
          }
          this.refresh();
          break;
        }
        case 'enableGlobalProxy': {
          await AgentAuditor.configureGlobalProxy(this.config.proxyPort);
          vscode.window.showInformationMessage(`🛡️ Argus: Global IDE Proxy enabled on port ${this.config.proxyPort}! Outbound traffic routed through Argus.`);
          this.refresh();
          break;
        }
      }
    });
  }

  public refresh(): void {
    if (this._view) {
      this._view.webview.html = this.getHtmlForWebview(this._view.webview);
    }
  }

  private getHtmlForWebview(_webview: vscode.Webview): string {
    const isRunning = this.proxyServer.getIsRunning();
    const stats = this.auditLogger.getStats();
    const recentLogs = this.auditLogger.getRecentRecords().slice(0, 8);
    const audit = AgentAuditor.auditEnvironment(this.config.proxyPort);

    const logRows = recentLogs.length === 0
      ? `<div style="text-align: center; color: var(--vscode-descriptionForeground); padding: 16px; font-size: 12px;">No leaks detected yet. Safe & clean!</div>`
      : recentLogs.map(log => {
        const badgeColor = log.action === 'blocked' ? '#EF4444' : log.action === 'masked' ? '#3B82F6' : '#10B981';
        return `
          <div style="background: var(--vscode-editor-inactiveSelectionBackground); border-left: 3px solid ${badgeColor}; padding: 8px; margin-bottom: 6px; border-radius: 4px; font-size: 11px;">
            <div style="display: flex; justify-content: space-between; margin-bottom: 4px;">
              <span style="font-weight: 600; color: ${badgeColor}; text-transform: uppercase;">${log.action}</span>
              <span style="color: var(--vscode-descriptionForeground); font-size: 10px;">${new Date(log.timestamp).toLocaleTimeString()} (${log.durationMs}ms)</span>
            </div>
            <div style="color: var(--vscode-foreground); margin-bottom: 4px; font-family: monospace;">${log.promptSnippet}</div>
            <div style="display: flex; gap: 4px; flex-wrap: wrap;">
              ${log.categories.map(c => `<span style="background: var(--vscode-badge-background); color: var(--vscode-badge-foreground); padding: 1px 5px; border-radius: 3px; font-size: 9px;">${c}</span>`).join('')}
            </div>
          </div>
        `;
      }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <style>
    body {
      font-family: var(--vscode-font-family);
      color: var(--vscode-foreground);
      padding: 12px;
      margin: 0;
      font-size: 12px;
      line-height: 1.4;
    }
    .header-card {
      background: var(--vscode-editor-background);
      border: 1px solid var(--vscode-widget-border, #333);
      border-radius: 6px;
      padding: 12px;
      margin-bottom: 12px;
    }
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 8px;
      border-radius: 12px;
      font-weight: 600;
      font-size: 11px;
    }
    .status-active { background: #064E3B; color: #34D399; }
    .status-inactive { background: #7F1D1D; color: #F87171; }
    .stats-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 8px;
      margin-bottom: 12px;
    }
    .stat-box {
      background: var(--vscode-editor-inactiveSelectionBackground);
      padding: 10px;
      border-radius: 6px;
      text-align: center;
    }
    .stat-number {
      font-size: 20px;
      font-weight: bold;
      color: var(--vscode-textLink-activeForeground);
    }
    .btn {
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      padding: 6px 12px;
      border-radius: 4px;
      cursor: pointer;
      font-size: 11px;
      font-weight: 500;
      width: 100%;
      margin-top: 6px;
    }
    .btn:hover { background: var(--vscode-button-hoverBackground); }
    .btn-secondary {
      background: var(--vscode-button-secondaryBackground);
      color: var(--vscode-button-secondaryForeground);
    }
    textarea {
      width: 100%;
      box-sizing: border-box;
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border);
      border-radius: 4px;
      padding: 6px;
      font-family: var(--vscode-editor-font-family);
      font-size: 11px;
      resize: vertical;
    }
    .mode-select {
      width: 100%;
      background: var(--vscode-dropdown-background);
      color: var(--vscode-dropdown-foreground);
      border: 1px solid var(--vscode-dropdown-border);
      padding: 4px;
      border-radius: 4px;
      margin-top: 4px;
    }
  </style>
</head>
<body>
  <div class="header-card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <span style="font-size: 13px; font-weight: bold;">🛡️ Argus Panoptes DLP</span>
      <span class="status-badge ${isRunning ? 'status-active' : 'status-inactive'}">
        ● ${isRunning ? 'ACTIVE' : 'STOPPED'}
      </span>
    </div>
    <div style="font-size: 11px; color: var(--vscode-descriptionForeground);">
      Proxy: <code>http://${this.config.proxyHost}:${this.config.proxyPort}/v1</code><br>
      Target: <code>${this.config.targetBaseUrl}</code> (${this.config.targetProvider})
    </div>
    <button id="toggleBtn" class="btn ${isRunning ? 'btn-secondary' : ''}">
      ${isRunning ? 'Stop DLP Proxy' : 'Start DLP Proxy'}
    </button>
  </div>

  <div class="stats-grid">
    <div class="stat-box">
      <div class="stat-number">${stats.totalLeaksPrevented}</div>
      <div style="font-size: 10px; color: var(--vscode-descriptionForeground);">Leaks Blocked/Masked</div>
    </div>
    <div class="stat-box">
      <div class="stat-number">${stats.totalScans}</div>
      <div style="font-size: 10px; color: var(--vscode-descriptionForeground);">Prompts Audited</div>
    </div>
  </div>

  <div class="header-card">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
      <span style="font-weight: 600;">🤖 AI Agent Egress & Shield</span>
      <span style="font-size: 10px; background: var(--vscode-badge-background); padding: 2px 6px; border-radius: 8px;">
        ${audit.detectedAgents.length} Agent(s)
      </span>
    </div>
    <div style="font-size: 11px; margin-bottom: 8px;">
      ${audit.detectedAgents.map(a => `
        <div style="padding: 4px 0; border-bottom: 1px solid var(--vscode-widget-border, #2a2a2a);">
          <div style="display: flex; justify-content: space-between;">
            <b>${a.name}</b>
            <span style="color: ${a.status === 'guarded' ? '#34D399' : '#F87171'}; font-weight: 600; font-size: 10px;">
              ${a.status === 'guarded' ? '🛡️ GUARDED' : '⚠️ DIRECT CLOUD'}
            </span>
          </div>
          <div style="font-size: 10px; color: var(--vscode-descriptionForeground); margin-top: 2px;">${a.details}</div>
        </div>
      `).join('')}
    </div>
    <div style="display: flex; gap: 6px;">
      <button id="aiIgnoreBtn" class="btn btn-secondary" style="font-size: 10px; padding: 4px 6px;">
        ${audit.aiIgnoreActive ? '✅ .aiignore Active' : '🛡️ Create .aiignore'}
      </button>
      <button id="globalProxyBtn" class="btn btn-secondary" style="font-size: 10px; padding: 4px 6px;">
        ${audit.globalProxyConfigured ? '✅ Global Proxy Active' : '🌐 Route IDE Proxy'}
      </button>
    </div>
  </div>

  <div class="header-card">
    <div style="font-weight: 600; margin-bottom: 4px;">Guardrail Policy</div>
    <select id="modeSelect" class="mode-select">
      <option value="mask" ${this.config.mode === 'mask' ? 'selected' : ''}>Mask (Sanitize & Unmask on Return)</option>
      <option value="block" ${this.config.mode === 'block' ? 'selected' : ''}>Block Prompt Completely</option>
      <option value="confirm" ${this.config.mode === 'confirm' ? 'selected' : ''}>Confirm with Diff Modal</option>
      <option value="audit_only" ${this.config.mode === 'audit_only' ? 'selected' : ''}>Audit Only (Log Without Action)</option>
    </select>
  </div>

  <div class="header-card">
    <div style="font-weight: 600; margin-bottom: 4px;">Interactive Prompt Scanner</div>
    <textarea id="testPrompt" rows="3" placeholder="Paste test prompt here (e.g. API key, Finnish HETU 010101-123N, etc.)..."></textarea>
    <button id="scanBtn" class="btn">Test Scan</button>
    <div id="scanResultBox" style="margin-top: 8px; font-size: 11px; display: none;"></div>
  </div>

  <div style="font-weight: 600; margin: 12px 0 6px 0; display: flex; justify-content: space-between; align-items: center;">
    <span>Recent Security Events</span>
    <button id="settingsBtn" style="background: none; border: none; color: var(--vscode-textLink-foreground); cursor: pointer; font-size: 11px;">Configure ⚙️</button>
  </div>

  <div id="logsContainer">
    ${logRows}
  </div>

  <script>
    const vscode = acquireVsCodeApi();

    document.getElementById('toggleBtn').addEventListener('click', () => {
      vscode.postMessage({ type: 'toggleProxy' });
    });

    const aiIgnoreBtn = document.getElementById('aiIgnoreBtn');
    if (aiIgnoreBtn) {
      aiIgnoreBtn.addEventListener('click', () => {
        vscode.postMessage({ type: 'createAiIgnore' });
      });
    }

    const globalProxyBtn = document.getElementById('globalProxyBtn');
    if (globalProxyBtn) {
      globalProxyBtn.addEventListener('click', () => {
        vscode.postMessage({ type: 'enableGlobalProxy' });
      });
    }

    document.getElementById('modeSelect').addEventListener('change', (e) => {
      vscode.postMessage({ type: 'switchMode', mode: e.target.value });
    });

    document.getElementById('settingsBtn').addEventListener('click', () => {
      vscode.postMessage({ type: 'openSettings' });
    });

    document.getElementById('scanBtn').addEventListener('click', () => {
      const text = document.getElementById('testPrompt').value;
      vscode.postMessage({ type: 'testScan', text });
    });

    window.addEventListener('message', event => {
      const message = event.data;
      if (message.type === 'scanResult') {
        const box = document.getElementById('scanResultBox');
        box.style.display = 'block';
        const res = message.result;
        if (res.hasViolations) {
          box.innerHTML = '<div style="color: #F87171; font-weight: bold;">⚠️ Detected ' + res.totalViolations + ' violation(s) (' + res.scanDurationMs + 'ms):</div>' +
            '<ul style="margin: 4px 0; padding-left: 16px;">' +
            res.entities.map(e => '<li><b>' + e.name + '</b>: <span style="font-family: monospace;">' + e.redactedPlaceholder + '</span></li>').join('') +
            '</ul>' +
            '<div style="color: var(--vscode-descriptionForeground); margin-top: 4px;">Masked Output:</div>' +
            '<div style="background: var(--vscode-editor-inactiveSelectionBackground); padding: 4px; border-radius: 4px; font-family: monospace; white-space: pre-wrap;">' + res.sanitizedText + '</div>';
        } else {
          box.innerHTML = '<div style="color: #34D399; font-weight: bold;">✅ Clean! No sensitive data detected (' + res.scanDurationMs + 'ms).</div>';
        }
      }
    });
  </script>
</body>
</html>`;
  }
}

