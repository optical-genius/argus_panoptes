import * as vscode from 'vscode';
import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { getArgusConfig } from './config';
import { DlpEngine } from './scanner/dlpEngine';
import { SessionVault } from './vault/sessionVault';
import { AuditLogger } from './logger/auditLogger';
import { DlpProxyServer } from './proxy/dlpProxy';
import { ArgusStatusBar } from './views/statusBar';
import { ArgusDashboardViewProvider } from './views/dashboardView';
import { AgentAuditor } from './audit/agentAuditor';

let proxyServer: DlpProxyServer | null = null;
let statusBar: ArgusStatusBar | null = null;

export async function activate(context: vscode.ExtensionContext) {
  const config = getArgusConfig();
  const sessionVault = new SessionVault();
  const dlpEngine = new DlpEngine(config, sessionVault);
  const auditLogger = new AuditLogger(context.globalStorageUri?.fsPath);

  proxyServer = new DlpProxyServer(config, dlpEngine, auditLogger);
  statusBar = new ArgusStatusBar();

  // Register Webview View
  const dashboardProvider = new ArgusDashboardViewProvider(
    context.extensionUri,
    config,
    dlpEngine,
    auditLogger,
    proxyServer
  );

  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(
      ArgusDashboardViewProvider.viewType,
      dashboardProvider
    )
  );

  // Command: Start Proxy
  const startProxyCmd = vscode.commands.registerCommand('argus.startProxy', async () => {
    try {
      const port = await proxyServer!.start();
      const currentCfg = getArgusConfig();
      currentCfg.proxyPort = port;
      statusBar!.update(true, currentCfg);
      dashboardProvider.refresh();
      vscode.window.showInformationMessage(
        `🛡️ Argus DLP Guardian started on port ${port}! Intercepting AI traffic -> ${currentCfg.targetBaseUrl}`
      );
    } catch (err: any) {
      vscode.window.showErrorMessage(`Failed to start Argus DLP Proxy: ${err.message}`);
    }
  });

  // Command: Stop Proxy
  const stopProxyCmd = vscode.commands.registerCommand('argus.stopProxy', async () => {
    await proxyServer!.stop();
    statusBar!.update(false, getArgusConfig());
    dashboardProvider.refresh();
    vscode.window.showWarningMessage('🛡️ Argus DLP Guardian stopped. Traffic is no longer guarded.');
  });

  // Command: Restart Proxy
  const restartProxyCmd = vscode.commands.registerCommand('argus.restartProxy', async () => {
    await proxyServer!.stop();
    try {
      const port = await proxyServer!.start();
      statusBar!.update(true, getArgusConfig());
      dashboardProvider.refresh();
      vscode.window.showInformationMessage(`🛡️ Argus DLP Guardian restarted on port ${port}.`);
    } catch (err: any) {
      vscode.window.showErrorMessage(`Failed to restart Argus DLP Proxy: ${err.message}`);
    }
  });

  // Command: Scan Selection
  const scanSelectionCmd = vscode.commands.registerCommand('argus.scanSelection', async () => {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
      vscode.window.showInformationMessage('Open a file and select text to scan with Argus DLP.');
      return;
    }

    const selection = editor.selection;
    const text = selection.isEmpty ? editor.document.getText() : editor.document.getText(selection);

    // Bypass whitelist for explicit manual scans requested by the user
    const result = dlpEngine.scan(text, editor.document.fileName, true);

    if (result.hasViolations) {
      const names = Array.from(new Set(result.entities.map(e => e.name))).join(', ');
      const action = await vscode.window.showWarningMessage(
        `⚠️ Argus DLP found ${result.totalViolations} sensitive entity/entities: [${names}]`,
        'View Sanitized Text',
        'Open Dashboard'
      );

      if (action === 'View Sanitized Text') {
        const doc = await vscode.workspace.openTextDocument({
          content: result.sanitizedText,
          language: editor.document.languageId
        });
        await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
      } else if (action === 'Open Dashboard') {
        vscode.commands.executeCommand('argus.dashboardView.focus');
      }
    } else {
      vscode.window.showInformationMessage(`✅ Argus DLP: No confidential data detected (${result.scanDurationMs}ms). Safe!`);
    }
  });

  // Command: Test Target LLM Connection (LM Studio / Ollama)
  const testConnCmd = vscode.commands.registerCommand('argus.testTargetConnection', async () => {
    const currentCfg = getArgusConfig();
    vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `Pinging ${currentCfg.targetProvider} at ${currentCfg.targetBaseUrl}...`,
        cancellable: false
      },
      async () => {
        try {
          const targetUrl = new URL(currentCfg.targetBaseUrl);
          const isHttps = targetUrl.protocol === 'https:';
          const client = isHttps ? https : http;

          const options = {
            hostname: targetUrl.hostname,
            port: targetUrl.port || (isHttps ? 443 : 80),
            path: targetUrl.pathname.replace(/\/$/, '') + '/models',
            method: 'GET',
            headers: {
              Authorization: `Bearer ${currentCfg.targetApiKey}`
            },
            timeout: 5000
          };

          await new Promise<void>((resolve, reject) => {
            const req = client.request(options, (res) => {
              if (res.statusCode && res.statusCode >= 200 && res.statusCode < 400) {
                vscode.window.showInformationMessage(
                  `✅ Connected successfully to ${currentCfg.targetProvider} (${currentCfg.targetBaseUrl})! Status: ${res.statusCode}`
                );
              } else {
                vscode.window.showWarningMessage(
                  `⚠️ Target server responded with status: ${res.statusCode} at ${currentCfg.targetBaseUrl}`
                );
              }
              resolve();
            });

            req.on('error', (err) => {
              reject(err);
            });

            req.on('timeout', () => {
              req.destroy();
              reject(new Error('Connection timed out after 5000ms. Is the server running?'));
            });

            req.end();
          });
        } catch (e: any) {
          vscode.window.showErrorMessage(
            `❌ Could not connect to ${currentCfg.targetProvider} at ${currentCfg.targetBaseUrl}. Ensure LM Studio / Ollama is running and port is correct. Error: ${e.message}`
          );
        }
      }
    );
  });

  // Command: Audit Active AI Agents
  const auditAgentsCmd = vscode.commands.registerCommand('argus.auditAgents', async () => {
    const currentCfg = getArgusConfig();
    const audit = AgentAuditor.auditEnvironment(currentCfg.proxyPort);
    const names = audit.detectedAgents.map(a => `${a.name} [${a.status.toUpperCase()}]`).join('\n• ');

    const choice = await vscode.window.showInformationMessage(
      `🛡️ Argus Agent Audit: ${audit.detectedAgents.length} agent(s) discovered.\n${audit.aiIgnoreActive ? '✅ .aiignore shield is active.' : '⚠️ No .aiignore file in workspace.'}`,
      'Open Dashboard',
      'Create .aiignore Shield',
      'Route Global Proxy'
    );

    if (choice === 'Open Dashboard') {
      vscode.commands.executeCommand('argus.dashboardView.focus');
    } else if (choice === 'Create .aiignore Shield') {
      vscode.commands.executeCommand('argus.enableAiIgnore');
    } else if (choice === 'Route Global Proxy') {
      vscode.commands.executeCommand('argus.enableGlobalProxy');
    }
  });

  // Command: Create .aiignore Shield
  const enableAiIgnoreCmd = vscode.commands.registerCommand('argus.enableAiIgnore', async () => {
    const success = AgentAuditor.createAiIgnoreFile();
    if (success) {
      vscode.window.showInformationMessage(
        '🛡️ Argus: Created .aiignore and .antigravityignore shields! Autonomous agents will be blocked from reading .env, secrets, and credentials.'
      );
      dashboardProvider.refresh();
    } else {
      vscode.window.showWarningMessage('Open a workspace folder first to generate AI ignore shield files.');
    }
  });

  // Command: Enable Global Proxy
  const enableGlobalProxyCmd = vscode.commands.registerCommand('argus.enableGlobalProxy', async () => {
    const currentCfg = getArgusConfig();
    await AgentAuditor.configureGlobalProxy(currentCfg.proxyPort);
    vscode.window.showInformationMessage(
      `🛡️ Argus: Global IDE Proxy set to http://127.0.0.1:${currentCfg.proxyPort}. All IDE and extension HTTP traffic now passes through Argus DLP.`
    );
    dashboardProvider.refresh();
  });

  // Command: Open Menu from Status Bar
  const openMenuCmd = vscode.commands.registerCommand('argus.openMenu', async () => {
    const currentCfg = getArgusConfig();
    const isRunning = proxyServer!.getIsRunning();

    const items: vscode.QuickPickItem[] = [
      {
        label: isRunning ? '$(stop) Stop DLP Proxy' : '$(play) Start DLP Proxy',
        description: isRunning ? `Listening on port :${currentCfg.proxyPort}` : 'Guard is paused'
      },
      {
        label: '$(dashboard) Open Security Dashboard & Audit Log',
        description: 'View metrics, live audit logs, and test prompts'
      },
      {
        label: '$(law) Change Guardrail Policy Mode',
        description: `Current mode: [${currentCfg.mode.toUpperCase()}]`
      },
      {
        label: '$(plug) Test Connection to Target LLM',
        description: `Target: ${currentCfg.targetBaseUrl} (${currentCfg.targetProvider})`
      },
      {
        label: '$(shield) Create AI Ignore Shield (.aiignore)',
        description: 'Block agents from reading secret files (.env, keys)'
      },
      {
        label: '$(globe) Route Global IDE Traffic through Argus',
        description: `Set http.proxy to http://127.0.0.1:${currentCfg.proxyPort}`
      },
      {
        label: '$(search) Scan Current File / Selection for Leaks',
        description: 'Run deep scan on current editor document'
      },
      {
        label: '$(gear) Configure Settings',
        description: 'Open full Argus settings in VS Code / Antigravity'
      }
    ];

    const selected = await vscode.window.showQuickPick(items, {
      placeHolder: '🛡️ Argus Panoptes DLP Guardrail: Choose an action'
    });

    if (!selected) {
      return;
    }

    if (selected.label.includes('Start DLP Proxy')) {
      vscode.commands.executeCommand('argus.startProxy');
    } else if (selected.label.includes('Stop DLP Proxy')) {
      vscode.commands.executeCommand('argus.stopProxy');
    } else if (selected.label.includes('Open Security Dashboard')) {
      vscode.commands.executeCommand('argus.dashboardView.focus');
    } else if (selected.label.includes('Change Guardrail Policy Mode')) {
      const modeChoice = await vscode.window.showQuickPick(
        [
          { label: 'mask', description: 'Mask sensitive entities and unmask in response (Recommended)' },
          { label: 'block', description: 'Completely reject prompt if violations are found' },
          { label: 'confirm', description: 'Show modal confirmation window with diff preview' },
          { label: 'audit_only', description: 'Allow all traffic through, but log leaks to audit file' }
        ],
        { placeHolder: 'Select Guardrail Mode' }
      );
      if (modeChoice) {
        await vscode.workspace.getConfiguration('argus').update('mode', modeChoice.label, vscode.ConfigurationTarget.Global);
        vscode.window.showInformationMessage(`Policy updated to: ${modeChoice.label.toUpperCase()}`);
      }
    } else if (selected.label.includes('Test Connection')) {
      vscode.commands.executeCommand('argus.testTargetConnection');
    } else if (selected.label.includes('Create AI Ignore')) {
      vscode.commands.executeCommand('argus.enableAiIgnore');
    } else if (selected.label.includes('Route Global IDE Traffic')) {
      vscode.commands.executeCommand('argus.enableGlobalProxy');
    } else if (selected.label.includes('Scan Current File')) {
      vscode.commands.executeCommand('argus.scanSelection');
    } else if (selected.label.includes('Configure Settings')) {
      vscode.commands.executeCommand('workbench.action.openSettings', 'argus');
    }
  });

  // Watch for configuration changes
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(async (e) => {
      if (e.affectsConfiguration('argus')) {
        const newCfg = getArgusConfig();
        dlpEngine.updateConfig(newCfg);
        proxyServer!.updateConfig(newCfg);
        statusBar!.update(proxyServer!.getIsRunning(), newCfg);
        dashboardProvider.updateConfig(newCfg);
      }
    })
  );

  // Agentic Protection: Warn if an agent attempts to inspect .env or credentials
  if (config.agentProtection.blockEnvFiles) {
    context.subscriptions.push(
      vscode.workspace.onDidOpenTextDocument((doc) => {
        const fileName = doc.fileName.toLowerCase();
        if (fileName.endsWith('.env') || fileName.includes('id_rsa') || fileName.includes('secrets.json')) {
          vscode.window.showWarningMessage(
            `🛡️ [Argus Guard] Opened sensitive file (${doc.fileName.split(/[\\/]/).pop()}). Argus DLP will prevent agent prompts from exfiltrating this file.`,
            'OK'
          );
        }
      })
    );
  }

  // Register commands to subscriptions
  context.subscriptions.push(
    startProxyCmd,
    stopProxyCmd,
    restartProxyCmd,
    scanSelectionCmd,
    testConnCmd,
    openMenuCmd,
    auditAgentsCmd,
    enableAiIgnoreCmd,
    enableGlobalProxyCmd
  );

  // Auto-start proxy if enabled in configuration
  if (config.enabled) {
    try {
      const port = await proxyServer.start();
      config.proxyPort = port;
      statusBar.update(true, config);
    } catch (err: any) {
      statusBar.update(false, config);
      vscode.window.showErrorMessage(
        `🛡️ Argus DLP could not bind to port ${config.proxyPort}: ${err.message}. You can change the port in Settings.`
      );
    }
  } else {
    statusBar.update(false, config);
  }
}

export async function deactivate() {
  if (proxyServer) {
    await proxyServer.stop();
  }
  if (statusBar) {
    statusBar.dispose();
  }
}

