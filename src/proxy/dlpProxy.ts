import * as http from 'http';
import * as https from 'https';
import { URL } from 'url';
import { ArgusConfig } from '../scanner/types';
import { DlpEngine } from '../scanner/dlpEngine';
import { AuditLogger } from '../logger/auditLogger';
import { SessionVault } from '../vault/sessionVault';

type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

interface JsonInspection {
  keys: string[];
  values: string[];
  supported: boolean;
}

function isJsonObject(value: unknown): value is { [key: string]: JsonValue } {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function inspectJson(value: unknown, inspection: JsonInspection): void {
  if (typeof value === 'string') {
    inspection.values.push(value);
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      inspectJson(item, inspection);
    }
    return;
  }

  if (isJsonObject(value)) {
    for (const [key, item] of Object.entries(value)) {
      inspection.keys.push(key);
      inspectJson(item, inspection);
    }
    return;
  }

  if (value !== null && typeof value !== 'boolean' && typeof value !== 'number') {
    inspection.supported = false;
  }
}

function sanitizeStringValues(value: unknown, engine: DlpEngine): JsonValue {
  if (typeof value === 'string') {
    return engine.scan(value).sanitizedText;
  }

  if (Array.isArray(value)) {
    return value.map(item => sanitizeStringValues(item, engine));
  }

  if (isJsonObject(value)) {
    const sanitized: { [key: string]: JsonValue } = {};
    for (const [key, item] of Object.entries(value)) {
      sanitized[key] = sanitizeStringValues(item, engine);
    }
    return sanitized;
  }

  return value as JsonValue;
}

function containsProperty(value: unknown, propertyName: string): boolean {
  if (Array.isArray(value)) {
    return value.some(item => containsProperty(item, propertyName));
  }

  if (isJsonObject(value)) {
    return Object.entries(value).some(([key, item]) =>
      key === propertyName || containsProperty(item, propertyName)
    );
  }

  return false;
}

export class DlpProxyServer {
  private server: http.Server | null = null;
  private config: ArgusConfig;
  private dlpEngine: DlpEngine;
  private auditLogger: AuditLogger;
  private isRunning: boolean = false;

  constructor(config: ArgusConfig, dlpEngine: DlpEngine, auditLogger: AuditLogger) {
    this.config = config;
    this.dlpEngine = dlpEngine;
    this.auditLogger = auditLogger;
  }

  public updateConfig(config: ArgusConfig): void {
    this.config = config;
    this.dlpEngine.updateConfig(config);
  }

  public getIsRunning(): boolean {
    return this.isRunning;
  }

  public start(): Promise<number> {
    return new Promise((resolve, reject) => {
      if (this.server && this.isRunning) {
        resolve(this.config.proxyPort);
        return;
      }

      let portToTry = this.config.proxyPort;
      const maxRetries = 10;
      let attempt = 0;

      const tryBind = (port: number) => {
        const srv = http.createServer((req, res) => {
          this.handleRequest(req, res);
        });

        srv.on('error', (err: any) => {
          if (err.code === 'EADDRINUSE' && attempt < maxRetries) {
            attempt++;
            portToTry = port + 1;
            try {
              srv.close();
            } catch {}
            tryBind(portToTry);
          } else {
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

  public stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.isRunning = false;
          this.server = null;
          resolve();
        });
      } else {
        this.isRunning = false;
        resolve();
      }
    });
  }

  private handleRequest(req: http.IncomingMessage, res: http.ServerResponse): void {
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
        } catch (e: any) {
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

  private handleCompletionsProxy(req: http.IncomingMessage, res: http.ServerResponse): void {
    this.collectBody(req, (rawBody) => {
      let payload: unknown;
      try {
        payload = JSON.parse(rawBody) as unknown;
      } catch {
        this.writeJsonError(res, 400, 'invalid_json', 'Request was not forwarded because its JSON payload could not be scanned safely.');
        return;
      }

      if (this.config.agentProtection.inspectToolCalls === false && containsProperty(payload, 'tool_calls')) {
        this.writeJsonError(res, 501, 'tool_call_inspection_disabled', 'Request was not forwarded because tool-call inspection is disabled.');
        return;
      }

      if (!isJsonObject(payload)) {
        this.writeJsonError(res, 400, 'unsupported_json_structure', 'Request was not forwarded because the JSON root must be an object.');
        return;
      }

      const requestEngine = new DlpEngine(this.config, new SessionVault());
      const inspection: JsonInspection = { keys: [], values: [], supported: true };
      inspectJson(payload, inspection);
      if (!inspection.supported) {
        this.writeJsonError(res, 400, 'unsupported_json_structure', 'Request was not forwarded because the JSON structure could not be scanned safely.');
        return;
      }

      const combinedText = inspection.values.join('\n');
      const scanResult = requestEngine.scan(combinedText);

      if (this.config.enabled) {
        const keyViolation = inspection.keys
          .map(key => ({ key, scan: requestEngine.scan(key) }))
          .find(item => item.scan.hasViolations);

        if (keyViolation) {
          const violationsSummary = keyViolation.scan.entities
            .map(e => `${e.name} (${e.category})`)
            .join(', ');
          this.auditLogger.logEvent('blocked', keyViolation.scan, keyViolation.key, this.getModelName(payload));
          this.writeJsonError(res, 400, 'sensitive_json_key', `Request blocked: protected data was found in a JSON key (${violationsSummary}).`);
          return;
        }
      }

      if (scanResult.hasViolations && this.config.enabled) {
        const violationsSummary = scanResult.entities
          .map(e => `${e.name} (${e.category})`)
          .join(', ');

        // Policy 1: BLOCK
        if (this.config.mode === 'block') {
          this.auditLogger.logEvent('blocked', scanResult, combinedText, this.getModelName(payload));
          this.writeDlpBlocked(res, 403, violationsSummary, scanResult);
          return;
        }

        // Policy 2: MASK (Sanitize & Unmask on return)
        if (this.config.mode === 'mask') {
          this.auditLogger.logEvent('masked', scanResult, combinedText, this.getModelName(payload));
          const sanitizedPayload = sanitizeStringValues(payload, requestEngine);
          const sanitizedBody = JSON.stringify(sanitizedPayload);
          this.forwardAndTransform(req, res, sanitizedBody, this.isStreamingPayload(payload), requestEngine.getVault());
          return;
        }

        // Policy 3: CONFIRM. The proxy has no interactive UI channel, so it
        // must fail closed instead of pretending that a user approved the leak.
        if (this.config.mode === 'confirm') {
          this.auditLogger.logEvent('blocked', scanResult, combinedText, this.getModelName(payload));
          this.writeJsonError(res, 428, 'confirmation_required', `Request blocked: confirmation is required before sending detected data (${violationsSummary}).`);
          return;
        }

        // Policy 4: AUDIT ONLY. This mode intentionally forwards after a
        // successful scan and records the finding.
        if (this.config.mode === 'audit_only') {
          this.auditLogger.logEvent('audited_pass', scanResult, combinedText, this.getModelName(payload));
        }
      }

      // Clean prompt or audit_only: forward as is after successful parsing.
      this.forwardAndTransform(req, res, rawBody, this.isStreamingPayload(payload), requestEngine.getVault());
    });
  }

  private forwardAndTransform(
    clientReq: http.IncomingMessage,
    clientRes: http.ServerResponse,
    bodyToSend: string,
    isStream: boolean,
    vault: SessionVault
  ): void {
    const targetUrl = new URL(this.config.targetBaseUrl);
    // Append path
    const requestPath = clientReq.url || '/v1/chat/completions';
    const targetPath = targetUrl.pathname.replace(/\/$/, '') + '/' + requestPath.replace(/^\/(?:v1\/)?/, '');

    const isHttps = targetUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const headers: Record<string, string> = {
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
            const unmaskedData = vault.unmaskText(respData);

            clientRes.writeHead(statusCode, {
              ...this.forwardResponseHeaders(targetRes.headers),
              'content-length': Buffer.byteLength(unmaskedData)
            });
            clientRes.end(unmaskedData);
          } catch {
            clientRes.writeHead(statusCode, targetRes.headers);
            clientRes.end(respData);
          }
        });
      } else {
        // Handle Server-Sent Events (SSE) streaming
        clientRes.writeHead(statusCode, this.forwardResponseHeaders(targetRes.headers));
        let pendingChunk = '';

        targetRes.on('data', (chunk) => {
          pendingChunk += chunk.toString('utf8');
          const tokenStart = pendingChunk.lastIndexOf('<ARGUS_');
          const tokenEnd = tokenStart >= 0 ? pendingChunk.indexOf('>', tokenStart) : -1;

          if (tokenStart >= 0 && tokenEnd < 0) {
            const flushable = pendingChunk.slice(0, tokenStart);
            if (flushable) {
              clientRes.write(vault.unmaskText(flushable));
            }
            pendingChunk = pendingChunk.slice(tokenStart);
            return;
          }

          clientRes.write(vault.unmaskText(pendingChunk));
          pendingChunk = '';
        });

        targetRes.on('end', () => {
          if (pendingChunk) {
            clientRes.write(vault.unmaskText(pendingChunk));
          }
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

  private forwardDirect(clientReq: http.IncomingMessage, clientRes: http.ServerResponse): void {
    const targetUrl = new URL(this.config.targetBaseUrl);
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

  private collectBody(req: http.IncomingMessage, callback: (body: string) => void): void {
    let body = '';
    req.on('data', chunk => {
      body += chunk.toString();
    });
    req.on('end', () => {
      callback(body);
    });
  }

  private isStreamingPayload(payload: unknown): boolean {
    return isJsonObject(payload) && payload.stream === true;
  }

  private getModelName(payload: unknown): string {
    return isJsonObject(payload) && typeof payload.model === 'string' ? payload.model : 'unknown';
  }

  private writeDlpBlocked(
    res: http.ServerResponse,
    statusCode: number,
    violationsSummary: string,
    scanResult: ReturnType<DlpEngine['scan']>
  ): void {
    const errorBody = {
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
    };
    this.writeJson(res, statusCode, errorBody);
  }

  private writeJsonError(res: http.ServerResponse, statusCode: number, type: string, message: string): void {
    this.writeJson(res, statusCode, { error: { message, type } });
  }

  private writeJson(res: http.ServerResponse, statusCode: number, body: unknown): void {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body));
  }

  private forwardResponseHeaders(headers: http.IncomingHttpHeaders): http.OutgoingHttpHeaders {
    const excludedHeaders = new Set([
      'connection',
      'content-length',
      'keep-alive',
      'transfer-encoding'
    ]);
    const forwarded: http.OutgoingHttpHeaders = {};
    for (const [name, value] of Object.entries(headers)) {
      if (value !== undefined && !excludedHeaders.has(name.toLowerCase())) {
        forwarded[name] = value;
      }
    }
    return forwarded;
  }
}

