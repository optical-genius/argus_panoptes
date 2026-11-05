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
exports.DlpProxyServer = void 0;
const http = __importStar(require("http"));
const https = __importStar(require("https"));
const url_1 = require("url");
class DlpProxyServer {
    server = null;
    config;
    dlpEngine;
    auditLogger;
    isRunning = false;
    constructor(config, dlpEngine, auditLogger) {
        this.config = config;
        this.dlpEngine = dlpEngine;
        this.auditLogger = auditLogger;
    }
    updateConfig(config) {
        this.config = config;
        this.dlpEngine.updateConfig(config);
    }
    getIsRunning() {
        return this.isRunning;
    }
    start() {
        return new Promise((resolve, reject) => {
            if (this.server && this.isRunning) {
                resolve(this.config.proxyPort);
                return;
            }
            let portToTry = this.config.proxyPort;
            const maxRetries = 10;
            let attempt = 0;
            const tryBind = (port) => {
                const srv = http.createServer((req, res) => {
                    this.handleRequest(req, res);
                });
                srv.on('error', (err) => {
                    if (err.code === 'EADDRINUSE' && attempt < maxRetries) {
                        attempt++;
                        portToTry = port + 1;
                        try {
                            srv.close();
                        }
                        catch { }
                        tryBind(portToTry);
                    }
                    else {
                        this.isRunning = false;
                        reject(err);
                    }
                });
                srv.listen(port, this.config.proxyHost, () => {
                    this.server = srv;
                    this.isRunning = true;
                    this.config.proxyPort = port;
                    resolve(port);
                });
            };
            tryBind(portToTry);
        });
    }
    stop() {
        return new Promise((resolve) => {
            if (this.server) {
                this.server.close(() => {
                    this.isRunning = false;
                    this.server = null;
                    resolve();
                });
            }
            else {
                this.isRunning = false;
                resolve();
            }
        });
    }
    handleRequest(req, res) {
        // Add CORS headers for IDE webviews and browser-based AI tooling
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');
        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            res.end();
            return;
        }
        const url = req.url || '';
        // Health check endpoint
        if (url === '/health' || url === '/api/status') {
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                status: 'ok',
                service: 'Argus Panoptes DLP Proxy',
                guardEnabled: this.config.enabled,
                mode: this.config.mode,
                targetUrl: this.config.targetBaseUrl
            }));
            return;
        }
        // Direct scan endpoint (used by VS Code / Antigravity commands)
        if (url === '/api/scan' && req.method === 'POST') {
            this.collectBody(req, (bodyStr) => {
                try {
                    const parsed = JSON.parse(bodyStr);
                    const text = parsed.text || '';
                    const result = this.dlpEngine.scan(text, parsed.filePath);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify(result));
                }
                catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: e.message }));
                }
            });
            return;
        }
        // Proxy completions requests
        if (req.method === 'POST' && (url.includes('/chat/completions') || url.includes('/completions'))) {
            this.handleCompletionsProxy(req, res);
            return;
        }
        // Forward any other requests (e.g. GET /v1/models) directly to target
        this.forwardDirect(req, res);
    }
    handleCompletionsProxy(req, res) {
        this.collectBody(req, (rawBody) => {
            try {
                const payload = JSON.parse(rawBody);
                let combinedText = '';
                if (Array.isArray(payload.messages)) {
                    combinedText = payload.messages
                        .map((m) => (typeof m.content === 'string' ? m.content : ''))
                        .join('\n');
                }
                else if (typeof payload.prompt === 'string') {
                    combinedText = payload.prompt;
                }
                const scanResult = this.dlpEngine.scan(combinedText);
                if (scanResult.hasViolations && this.config.enabled) {
                    const violationsSummary = scanResult.entities
                        .map(e => `${e.name} (${e.category})`)
                        .join(', ');
                    // Policy 1: BLOCK
                    if (this.config.mode === 'block') {
                        this.auditLogger.logEvent('blocked', scanResult, combinedText, payload.model || 'unknown');
                        res.writeHead(403, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({
                            error: {
                                message: `🛡️ [Argus Panoptes DLP] Request blocked! Confidential data detected: ${violationsSummary}`,
                                type: 'dlp_violation',
                                code: 'argus_leak_prevention',
                                violations: scanResult.entities.map(e => ({
                                    category: e.category,
                                    name: e.name,
                                    severity: e.severity
                                }))
                            }
                        }));
                        return;
                    }
                    // Policy 2: MASK (Sanitize & Unmask on return)
                    if (this.config.mode === 'mask') {
                        this.auditLogger.logEvent('masked', scanResult, combinedText, payload.model || 'unknown');
                        // Sanitize each message individually
                        if (Array.isArray(payload.messages)) {
                            for (const msg of payload.messages) {
                                if (typeof msg.content === 'string') {
                                    const msgScan = this.dlpEngine.scan(msg.content);
                                    msg.content = msgScan.sanitizedText;
                                }
                            }
                        }
                        else if (typeof payload.prompt === 'string') {
                            payload.prompt = scanResult.sanitizedText;
                        }
                        const sanitizedBody = JSON.stringify(payload);
                        this.forwardAndTransform(req, res, sanitizedBody, payload.stream === true);
                        return;
                    }
                    // Policy 3: AUDIT ONLY
                    if (this.config.mode === 'audit_only') {
                        this.auditLogger.logEvent('audited_pass', scanResult, combinedText, payload.model || 'unknown');
                    }
                }
                // Clean prompt or audit_only: forward as is
                this.forwardAndTransform(req, res, rawBody, payload.stream === true);
            }
            catch (err) {
                // Fallback: forward raw if JSON parsing failed
                this.forwardAndTransform(req, res, rawBody, false);
            }
        });
    }
    forwardAndTransform(clientReq, clientRes, bodyToSend, isStream) {
        const targetUrl = new url_1.URL(this.config.targetBaseUrl);
        // Append path
        const requestPath = clientReq.url || '/v1/chat/completions';
        const targetPath = targetUrl.pathname.replace(/\/$/, '') + '/' + requestPath.replace(/^\/(?:v1\/)?/, '');
        const isHttps = targetUrl.protocol === 'https:';
        const client = isHttps ? https : http;
        const headers = {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(bodyToSend).toString(),
            'Authorization': clientReq.headers.authorization || `Bearer ${this.config.targetApiKey}`
        };
        const options = {
            hostname: targetUrl.hostname,
            port: targetUrl.port || (isHttps ? 443 : 80),
            path: targetPath,
            method: clientReq.method,
            headers
        };
        const targetReq = client.request(options, (targetRes) => {
            const statusCode = targetRes.statusCode || 200;
            if (!isStream) {
                let respData = '';
                targetRes.on('data', (chunk) => {
                    respData += chunk;
                });
                targetRes.on('end', () => {
                    try {
                        // Unmask placeholders in target LLM response before returning to IDE
                        const unmaskedData = this.dlpEngine.getVault().unmaskText(respData);
                        clientRes.writeHead(statusCode, {
                            ...targetRes.headers,
                            'content-length': Buffer.byteLength(unmaskedData)
                        });
                        clientRes.end(unmaskedData);
                    }
                    catch {
                        clientRes.writeHead(statusCode, targetRes.headers);
                        clientRes.end(respData);
                    }
                });
            }
            else {
                // Handle Server-Sent Events (SSE) streaming
                clientRes.writeHead(statusCode, targetRes.headers);
                targetRes.on('data', (chunk) => {
                    // Unmask streaming chunk text on the fly
                    const chunkStr = chunk.toString('utf8');
                    const unmaskedChunk = this.dlpEngine.getVault().unmaskText(chunkStr);
                    clientRes.write(unmaskedChunk);
                });
                targetRes.on('end', () => {
                    clientRes.end();
                });
            }
        });
        targetReq.on('error', (err) => {
            clientRes.writeHead(502, { 'Content-Type': 'application/json' });
            clientRes.end(JSON.stringify({
                error: {
                    message: `🛡️ [Argus Panoptes DLP] Unable to reach target model at ${this.config.targetBaseUrl}: ${err.message}`,
                    type: 'bad_gateway'
                }
            }));
        });
        targetReq.write(bodyToSend);
        targetReq.end();
    }
    forwardDirect(clientReq, clientRes) {
        const targetUrl = new url_1.URL(this.config.targetBaseUrl);
        const requestPath = clientReq.url || '/v1/models';
        const targetPath = targetUrl.pathname.replace(/\/$/, '') + '/' + requestPath.replace(/^\/(?:v1\/)?/, '');
        const isHttps = targetUrl.protocol === 'https:';
        const client = isHttps ? https : http;
        const options = {
            hostname: targetUrl.hostname,
            port: targetUrl.port || (isHttps ? 443 : 80),
            path: targetPath,
            method: clientReq.method,
            headers: {
                ...clientReq.headers,
                host: targetUrl.host,
                authorization: clientReq.headers.authorization || `Bearer ${this.config.targetApiKey}`
            }
        };
        const targetReq = client.request(options, (targetRes) => {
            clientRes.writeHead(targetRes.statusCode || 200, targetRes.headers);
            targetRes.pipe(clientRes);
        });
        targetReq.on('error', (err) => {
            clientRes.writeHead(502, { 'Content-Type': 'application/json' });
            clientRes.end(JSON.stringify({
                error: `🛡️ [Argus Panoptes DLP] Failed connecting to ${this.config.targetBaseUrl}: ${err.message}`
            }));
        });
        clientReq.pipe(targetReq);
    }
    collectBody(req, callback) {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            callback(body);
        });
    }
}
exports.DlpProxyServer = DlpProxyServer;
//# sourceMappingURL=dlpProxy.js.map