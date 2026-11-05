import { DetectedEntity } from '../scanner/types';

export interface VaultEntry {
  placeholder: string;
  originalValue: string;
  category: string;
  timestamp: number;
}

/**
 * Bidirectional Token Vault:
 * 1. Anonymizes sensitive entities in the prompt by replacing them with placeholders.
 * 2. Unmasks / re-identifies the placeholders when the LLM returns its response.
 *
 * This ensures the remote/local LLM never sees real secrets or PII,
 * while the developer in the IDE receives a coherent and complete answer.
 */
export class SessionVault {
  private tokenToOriginal: Map<string, VaultEntry> = new Map();
  private originalToToken: Map<string, string> = new Map();
  private categoryCounters: Map<string, number> = new Map();

  /**
   * Clears all session entries.
   */
  public clear(): void {
    this.tokenToOriginal.clear();
    this.originalToToken.clear();
    this.categoryCounters.clear();
  }

  /**
   * Generates or retrieves an existing placeholder token for a sensitive value.
   */
  public getOrCreateToken(originalValue: string, category: string): string {
    if (this.originalToToken.has(originalValue)) {
      return this.originalToToken.get(originalValue)!;
    }

    const currentCount = (this.categoryCounters.get(category) || 0) + 1;
    this.categoryCounters.set(category, currentCount);

    const placeholder = `<ARGUS_${category}_${currentCount}>`;

    const entry: VaultEntry = {
      placeholder,
      originalValue,
      category,
      timestamp: Date.now()
    };

    this.tokenToOriginal.set(placeholder, entry);
    this.originalToToken.set(originalValue, placeholder);

    return placeholder;
  }

  /**
   * Replaces all detected entities in the text with vault placeholders.
   * Processes entities from right to left (descending startIndex) to preserve text offsets.
   */
  public maskText(text: string, entities: DetectedEntity[]): string {
    if (!entities || entities.length === 0) {
      return text;
    }

    // Sort descending by startIndex
    const sorted = [...entities].sort((a, b) => b.startIndex - a.startIndex);
    let result = text;

    for (const entity of sorted) {
      const placeholder = this.getOrCreateToken(entity.matchedText, entity.category);
      entity.redactedPlaceholder = placeholder;

      result =
        result.slice(0, entity.startIndex) +
        placeholder +
        result.slice(entity.endIndex);
    }

    return result;
  }

  /**
   * Replaces placeholders back with their original sensitive values in the LLM's response.
   */
  public unmaskText(text: string): string {
    if (!text || this.tokenToOriginal.size === 0) {
      return text;
    }

    let unmasked = text;
    for (const [placeholder, entry] of this.tokenToOriginal.entries()) {
      // Replace all occurrences of placeholder
      unmasked = unmasked.split(placeholder).join(entry.originalValue);
    }

    return unmasked;
  }

  /**
   * Returns current active vault entries count.
   */
  public getEntryCount(): number {
    return this.tokenToOriginal.size;
  }
}

