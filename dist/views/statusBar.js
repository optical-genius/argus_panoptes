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
exports.ArgusStatusBar = void 0;
const vscode = __importStar(require("vscode"));
class ArgusStatusBar {
    statusBarItem;
    constructor() {
        this.statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
        this.statusBarItem.command = 'argus.openMenu';
    }
    update(isRunning, config) {
        if (!config.enabled) {
            this.statusBarItem.text = '$(shield) Argus: Off';
            this.statusBarItem.tooltip = 'Argus Panoptes DLP Guardrail is disabled in settings.';
            this.statusBarItem.backgroundColor = undefined;
        }
        else if (isRunning) {
            this.statusBarItem.text = `$(shield) Argus: Active (:${config.proxyPort})`;
            this.statusBarItem.tooltip = new vscode.MarkdownString(`### 🛡️ Argus Panoptes DLP Active\n\n` +
                `- **Proxy:** \`http://${config.proxyHost}:${config.proxyPort}/v1\`\n` +
                `- **Target:** \`${config.targetBaseUrl}\` (${config.targetProvider})\n` +
                `- **Policy:** \`${config.mode.toUpperCase()}\`\n\n` +
                `*Click to open control menu*`);
            this.statusBarItem.backgroundColor = undefined;
        }
        else {
            this.statusBarItem.text = '$(alert) Argus: Stopped';
            this.statusBarItem.tooltip = 'Argus Panoptes DLP Proxy is stopped. Click to start.';
            this.statusBarItem.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        }
        this.statusBarItem.show();
    }
    dispose() {
        this.statusBarItem.dispose();
    }
}
exports.ArgusStatusBar = ArgusStatusBar;
//# sourceMappingURL=statusBar.js.map