# Argus Panoptes: AI Data Leak Prevention (DLP) Extension

> **Smart DLP Guardrail for VS Code & Antigravity IDE**  
> Protects prompts, code context, and credentials from leaking to LM Studio, Ollama, and Cloud LLMs.

---

## 👁️ Overview

**Argus Panoptes** is an all-seeing DLP guardrail extension designed for developers and AI agents working in **Visual Studio Code** and **Antigravity IDE**.

When using AI assistants (GitHub Copilot, Continue.dev, Cline, or autonomous agents), sensitive data often ends up in prompt context:

- **API Keys & Secrets** (OpenAI, AWS, GitHub PATs, Stripe, SSH/RSA keys, Database URLs)
- **PII & Finnish Identity Codes** (Henkilötunnus / HETU with modulo-31 verification, IBAN with ISO-7064 check, Emails, Phones)
- **High-Entropy Strings** (Shannon Entropy scanner for unknown tokens and passwords)

---

## 🛡️ Key Features

1. **Local Proxy Gateway (OpenAI-compatible `/v1/chat/completions`)**:
   - Listens on `http://127.0.0.1:8765/v1` (auto-fallback if port is busy)
   - Intercepts prompts, scans and cleans them in real time (< 2ms latency)
   - Forwards to your local LLM (e.g. **LM Studio** on port `1234` or **Ollama** on port `11434`) or cloud models.

2. **Bidirectional Token Vault (Masking & Unmasking)**:
   - Replaces secrets with session tokens (`sk-proj-...` $\rightarrow$ `<ARGUS_API_KEY_1>`, `010101-123N` $\rightarrow$ `<ARGUS_FINNISH_HETU_1>`).
   - When the LLM responds, Argus automatically restores the original values back into the IDE on the fly, so you see real context while the model sees only tokens.

3. **Multi-Policy Modes**:
   - **Mask (Recommended)**: Anonymizes outgoing prompt and de-anonymizes LLM response.
   - **Block**: Rejects the prompt with HTTP 403 and shows the detected leaks in an alert.
   - **Confirm**: Displays interactive diff review before sending.
   - **Audit Only**: Allows prompt through but logs leaks to local audit history.

4. **Privacy-by-Design Local Audit Log**:
   - Stores audit history in `.argus/audit.jsonl`.
   - All sensitive entity values are hashed with SHA-256 fingerprints—no plain text secrets in logs!

5. **Antigravity IDE & Agent Protection**:
   - Monitors agent workspace reads and warns when `.env` or credential files are accessed.

---

## 🚀 Quick Start Guide

### 1. Build the Extension

```bash
cd argus_panoptes
npm install
npm run compile
npm test
```

### 2. Configure LM Studio / Ollama

1. Open **LM Studio**, start the Local Server on port `1234` (e.g. `http://localhost:1234`).
2. In VS Code or Antigravity IDE, open `Settings` $\rightarrow$ search `Argus`:
   - Set `argus.target.baseUrl` to `http://127.0.0.1:1234/v1` (or your Ollama address `http://127.0.0.1:11434/v1`).
   - Set `argus.proxy.port` to `8765`.
3. In your AI extension (e.g. Continue, Cline, or custom assistant), set the API Base URL to:
   ```
   http://127.0.0.1:8765/v1
   ```
4. Now all AI requests pass through the Argus Panoptes DLP Guardrail!

---

## 📊 Extension Architecture

```
argus_panoptes/
├── package.json          # Extension manifest & configuration schema
├── tsconfig.json         # TypeScript compiler configuration
├── src/
│   ├── extension.ts      # Activation, lifecycle, commands & event listeners
│   ├── config.ts         # Settings manager & reader
│   ├── proxy/
│   │   └── dlpProxy.ts   # Local HTTP proxy server (:8080 -> target)
│   ├── scanner/
│   │   ├── types.ts           # Interfaces & types
│   │   ├── dlpEngine.ts       # Main orchestrator & deduplication
│   │   ├── finnishHetu.ts     # Finnish HETU modulo-31 validator
│   │   ├── ibanValidator.ts   # IBAN ISO 7064 Modulo-97 validator
│   │   ├── regexScanner.ts    # Secrets, API keys, and PII patterns
│   │   └── entropy.ts         # Shannon entropy scanner
│   ├── vault/
│   │   └── sessionVault.ts    # Reversible bidirectional token vault
│   ├── logger/
│   │   └── auditLogger.ts     # Privacy-by-design SHA-256 audit logger
│   └── views/
│       ├── statusBar.ts       # Status bar item & quick menu
│       └── dashboardView.ts   # Activity Bar Security Dashboard & Webview
├── tests/
│   └── test_scanner.ts   # Automated unit test suite
└── server/               # Optional Python FastAPI sidecar for Presidio/spaCy ML
    ├── server.py
    └── recognizers/
```

---

## 🧪 Running Automated Tests

```bash
npm test
```

All unit tests verify:

- ✅ Finnish HETU date & checksum validation
- ✅ IBAN checksum validation
- ✅ Credit Card Luhn verification
- ✅ Shannon Entropy secret scanning
- ✅ Token Vault masking and response re-identification
- ✅ Full DlpEngine leak detection and severity classification
