import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { AuditRecord, DlpScanResult } from '../scanner/types';

export class AuditLogger {
  private static readonly fingerprintSalt = crypto.randomBytes(32);
  private logFilePath: string;
  private recentRecords: AuditRecord[] = [];
  private maxRecentRecords = 100;
  private onRecordAddedListeners: Array<(record: AuditRecord) => void> = [];

  constructor(storageDir?: string) {
    const dir = storageDir || path.join(process.cwd(), '.argus');
    try {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    } catch {
      // Fallback
    }
    this.logFilePath = path.join(dir, 'audit.jsonl');
    this.loadRecentRecords();
  }

  public onRecordAdded(listener: (record: AuditRecord) => void): void {
    this.onRecordAddedListeners.push(listener);
  }

  /**
   * Creates a process-local HMAC fingerprint for privacy-preserving auditing.
   * The random salt prevents offline dictionary matching from the log alone.
   */
  public static hashEntity(value: string): string {
    return crypto.createHmac('sha256', AuditLogger.fingerprintSalt).update(value).digest('hex').slice(0, 16);
  }

  /**
   * Logs a DLP scanning event.
   */
  public logEvent(
    action: 'masked' | 'blocked' | 'confirmed' | 'audited_pass',
    scanResult: DlpScanResult,
    rawPrompt: string,
    targetModel: string
  ): AuditRecord {
    // Take a short safe snippet of the prompt (first 80 chars, without secrets)
    const safeSnippet = scanResult.sanitizedText.slice(0, 80).replace(/[\r\n]+/g, ' ') + '...';

    const fingerprints = scanResult.entities.map(e =>
      `${e.category}:${AuditLogger.hashEntity(e.matchedText)}`
    );

    const record: AuditRecord = {
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      action,
      promptSnippet: safeSnippet,
      entityCount: scanResult.totalViolations,
      categories: Array.from(new Set(scanResult.entities.map(e => e.category))),
      entityFingerprints: fingerprints,
      targetModel,
      durationMs: scanResult.scanDurationMs
    };

    this.recentRecords.unshift(record);
    if (this.recentRecords.length > this.maxRecentRecords) {
      this.recentRecords.pop();
    }

    this.appendToFile(record);

    for (const listener of this.onRecordAddedListeners) {
      try {
        listener(record);
      } catch {
        // Ignore listener errors
      }
    }

    return record;
  }

  public getRecentRecords(): AuditRecord[] {
    return [...this.recentRecords];
  }

  public getStats(): { totalScans: number; totalLeaksPrevented: number; leaksByCategory: Record<string, number> } {
    const leaksByCategory: Record<string, number> = {};
    let totalLeaks = 0;

    for (const record of this.recentRecords) {
      totalLeaks += record.entityCount;
      for (const cat of record.categories) {
        leaksByCategory[cat] = (leaksByCategory[cat] || 0) + 1;
      }
    }

    return {
      totalScans: this.recentRecords.length,
      totalLeaksPrevented: totalLeaks,
      leaksByCategory
    };
  }

  private appendToFile(record: AuditRecord): void {
    try {
      const line = JSON.stringify(record) + '\n';
      fs.appendFileSync(this.logFilePath, line, 'utf8');
    } catch {
      // In-memory fallback if file write fails
    }
  }

  private loadRecentRecords(): void {
    try {
      if (fs.existsSync(this.logFilePath)) {
        const content = fs.readFileSync(this.logFilePath, 'utf8');
        const lines = content.trim().split('\n').filter(l => l.trim().length > 0);
        const records: AuditRecord[] = [];
        // Read last 100 lines
        const slice = lines.slice(-this.maxRecentRecords);
        for (const line of slice) {
          try {
            records.unshift(JSON.parse(line));
          } catch {
            // Ignore corrupted lines
          }
        }
        this.recentRecords = records;
      }
    } catch {
      this.recentRecords = [];
    }
  }
}

