/**
 * IBAN (International Bank Account Number) validator with ISO 7064 Modulo-97 check.
 */

export function validateIban(iban: string): boolean {
  const cleanIban = iban.replace(/[\s-]/g, '').toUpperCase();

  // Basic format: 2 country letters, 2 check digits, and 11-30 alphanumeric characters
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(cleanIban)) {
    return false;
  }

  // Move the first 4 characters to the end
  const rearranged = cleanIban.slice(4) + cleanIban.slice(0, 4);

  // Convert each letter to two digits (A = 10, B = 11, ..., Z = 35)
  let numericString = '';
  for (let i = 0; i < rearranged.length; i++) {
    const code = rearranged.charCodeAt(i);
    if (code >= 65 && code <= 90) {
      // Uppercase letter
      numericString += (code - 55).toString();
    } else {
      numericString += rearranged[i];
    }
  }

  // Perform modulo 97 on large numbers chunk by chunk
  let remainder = 0;
  for (let i = 0; i < numericString.length; i += 7) {
    const chunk = remainder.toString() + numericString.slice(i, i + 7);
    remainder = parseInt(chunk, 10) % 97;
  }

  return remainder === 1;
}

export function findIbans(text: string): Array<{ iban: string; index: number }> {
  const found: Array<{ iban: string; index: number }> = [];
  const startRegex = /\b[A-Z]{2}[0-9]{2}/gi;
  const minimumBodyLength = 11;
  const maximumBodyLength = 30;

  let match: RegExpExecArray | null;
  while ((match = startRegex.exec(text)) !== null) {
    const startIndex = match.index;
    const candidateEndIndexes: number[] = [];
    let cursor = startIndex + 4;
    let bodyLength = 0;

    // Consume at most the IBAN body. Separators are allowed between characters,
    // but words following an IBAN are considered only as validation candidates,
    // not as part of the accepted match.
    while (cursor < text.length && bodyLength < maximumBodyLength) {
      const current = text[cursor];
      if (/[A-Z0-9]/i.test(current)) {
        cursor++;
        bodyLength++;
        candidateEndIndexes.push(cursor);
        continue;
      }

      if ((current === ' ' || current === '-') && /[A-Z0-9]/i.test(text[cursor + 1] || '')) {
        cursor++;
        cursor++;
        bodyLength++;
        candidateEndIndexes.push(cursor);
        continue;
      }

      break;
    }

    // Choose the shortest valid prefix. This prevents a valid IBAN from
    // absorbing following words such as "as" or "and".
    for (const endIndex of candidateEndIndexes) {
      if (endIndex - (startIndex + 4) < minimumBodyLength) {
        continue;
      }

      const raw = text.slice(startIndex, endIndex);
      const nextCharacter = text[endIndex] || '';
      if (/[A-Z0-9]/i.test(nextCharacter)) {
        continue;
      }

      if (validateIban(raw)) {
        found.push({
          iban: raw,
          index: startIndex
        });
        startRegex.lastIndex = endIndex;
        break;
      }
    }
  }

  return found;
}

