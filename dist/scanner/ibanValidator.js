"use strict";
/**
 * IBAN (International Bank Account Number) validator with ISO 7064 Modulo-97 check.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateIban = validateIban;
exports.findIbans = findIbans;
function validateIban(iban) {
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
        }
        else {
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
function findIbans(text) {
    // Regex finding potential IBANs (e.g., FI21 1234 5600 0007 85 or FI2112345600000785)
    const ibanRegex = /\b[A-Z]{2}[0-9]{2}(?:\s?[0-9A-Z]{4}){2,7}\b/gi;
    const found = [];
    let match;
    while ((match = ibanRegex.exec(text)) !== null) {
        const raw = match[0];
        if (validateIban(raw)) {
            found.push({
                iban: raw,
                index: match.index
            });
        }
    }
    return found;
}
//# sourceMappingURL=ibanValidator.js.map