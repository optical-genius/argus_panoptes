import * as vscode from 'vscode';
import { ArgusConfig } from '../scanner/types';

export class ArgusStatusBar {
  private statusBarItem: vscode.StatusBarItem;

  constructor() {
    this.statusBarItem = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.statusBarItem.command = 'argus.openMenu';
  }

  public update(isRunning: boolean, config: ArgusConfig): void {
    if (!config.enabled) {
      this.statusBarItem.text = '$(shield) Argus: Off';
      this.statusBarItem.tooltip = 'Argus Panoptes DLP Guardrail is disabled in settings.';
      this.statusBarItem.backgroundColor = undefined;
    } else if (isRunning) {
      this.statusBarItem.text = `$(shield) Argus: Active (:${config.proxyPort})`;
      this.statusBarItem.tooltip = new vscode.MarkdownString(
        `### 🛡️ Argus Panoptes DLP Active\n\n` +
        `- **Proxy:** \`http://${config.proxyHost}:${config.proxyPort}/v1\`\n` +
        `- **Target:** \`${config.targetBaseUrl}\` (${config.targetProvider})\n` +
        `- **Policy:** \`${config.mode.toUpperCase()}\`\n\n` +
        `*Click to open control menu*`
      );
      this.statusBarItem.backgroundColor = undefined;
    } else {
      this.statusBarItem.text = '$(alert) Argus: Stopped';
      this.statusBarItem.tooltip = 'Argus Panoptes DLP Proxy is stopped. Click to start.';
      this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
    }

    this.statusBarItem.show();
  }

  public dispose(): void {
    this.statusBarItem.dispose();
  }
}

