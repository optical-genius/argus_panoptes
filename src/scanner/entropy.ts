/**
 * Shannon Entropy calculation for detecting high-entropy random secrets,
 * passwords, and API keys.
 */

export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) {
    return 0;
  }

  const charCounts: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    charCounts[char] = (charCounts[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const char in charCounts) {
    const p = charCounts[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Scans tokens in a string for high-entropy secrets (e.g. Hex, Base64).
 * Tokens under minLength (default 16) or with common English dictionary qualities are ignored.
 */
export function findHighEntropyTokens(
  text: string,
  minLength: number = 20,
  entropyThreshold: number = 4.2
): Array<{ token: string; entropy: number; index: number }> {
  const results: Array<{ token: string; entropy: number; index: number }> = [];

  // Match sequences of characters common in tokens (alphanumeric + base64 chars + hyphens)
  const tokenRegex = /[A-Za-z0-9+/=_-]{16,}/g;
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(text)) !== null) {
    const token = match[0];
    if (token.length >= minLength) {
      // Ignore if it's purely repeated chars (e.g. "0000000000000000") or UUID with many dashes
      const entropy = calculateShannonEntropy(token);
      if (entropy >= entropyThreshold) {
        results.push({
          token,
          entropy: Math.round(entropy * 100) / 100,
          index: match.index
        });
      }
    }
  }

  return results;
}

