/**
 * Finnish Personal Identity Code (Henkilötunnus / HETU) validator.
 * Validates syntax, date of birth, century marker, and the official modulo-31 checksum.
 * Supports modern 2023 DVV century characters (A, B, C, D, E, F).
 */

const HETU_CHECKSUM_CHARS = '0123456789ABCDEFHJKLMNPRSTUVWXY';

export function validateFinnishHetu(hetu: string): boolean {
  if (!hetu || hetu.length !== 11) {
    return false;
  }

  // Regex pattern: DDMMYY followed by century separator, 3 individual digits, and checksum char
  const pattern = /^(\d{2})(\d{2})(\d{2})([+\-A-Fa-fU-Yu-y])(\d{3})([0-9A-Za-z])$/;
  const match = pattern.exec(hetu);
  if (!match) {
    return false;
  }

  const day = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const yearShort = parseInt(match[3], 10);
  const separator = match[4].toUpperCase();
  const individualNumber = parseInt(match[5], 10);
  const checksumChar = match[6].toUpperCase();

  // Basic date validity
  if (day < 1 || day > 31 || month < 1 || month > 12) {
    return false;
  }

  // Century mapping
  let fullYear = 0;
  if (separator === '+') {
    fullYear = 1800 + yearShort;
  } else if (separator === '-') {
    fullYear = 1900 + yearShort;
  } else if (['A', 'B', 'C', 'D', 'E', 'F', 'U', 'V', 'W', 'X', 'Y'].includes(separator)) {
    fullYear = 2000 + yearShort;
  } else {
    return false;
  }

  // Check valid date with leap years
  const dateObj = new Date(fullYear, month - 1, day);
  if (
    dateObj.getFullYear() !== fullYear ||
    dateObj.getMonth() !== month - 1 ||
    dateObj.getDate() !== day
  ) {
    return false;
  }

  // Modulo-31 checksum calculation:
  // Concatenate DDMMYYNNN into a 9-digit number
  const numToDivide = parseInt(`${match[1]}${match[2]}${match[3]}${match[5]}`, 10);
  const remainder = numToDivide % 31;
  const expectedChar = HETU_CHECKSUM_CHARS[remainder];

  return checksumChar === expectedChar;
}

export function findFinnishHetus(text: string): Array<{ hetu: string; index: number }> {
  const hetuRegex = /\b\d{6}[+\-A-Fa-fU-Yu-y]\d{3}[0-9A-Za-z]\b/g;
  const found: Array<{ hetu: string; index: number }> = [];

  let match: RegExpExecArray | null;
  while ((match = hetuRegex.exec(text)) !== null) {
    if (validateFinnishHetu(match[0])) {
      found.push({
        hetu: match[0],
        index: match.index
      });
    }
  }

  return found;
}

