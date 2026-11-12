import { DetectionCategory, SensitivitySeverity } from './types';

export interface RegexRule {
  category: DetectionCategory;
  name: string;
  pattern: RegExp;
  severity: SensitivitySeverity;
  confidence: number;
}

/**
 * Validates Credit Card number using the Luhn Algorithm (Mod-10).
 */
export function validateLuhn(ccNumber: string): boolean {
  const digits = ccNumber.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(digits)) {
    return false;
  }

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

export const SECRET_RULES: RegexRule[] = [
  // Private Keys
  {
    category: DetectionCategory.PRIVATE_KEY,
    name: 'Private Encryption Key (RSA/EC/DSA/OpenSSH)',
    pattern: /-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY(?: BLOCK)?-----[\s\S]*?-----END\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE\s+KEY(?: BLOCK)?-----/g,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 1.0
  },
  // OpenAI API Key
  {
    category: DetectionCategory.API_KEY,
    name: 'OpenAI API Secret Key',
    pattern: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{32,80}\b/g,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 0.98
  },
  // Anthropic API Key
  {
    category: DetectionCategory.API_KEY,
    name: 'Anthropic Claude API Key',
    pattern: /\bsk-ant-(?:api03-)?[A-Za-z0-9_-]{40,100}\b/g,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 0.98
  },
  // GitHub Tokens
  {
    category: DetectionCategory.API_KEY,
    name: 'GitHub Personal Access / OAuth Token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b/g,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 0.99
  },
  {
    category: DetectionCategory.API_KEY,
    name: 'GitHub Fine-Grained Personal Access Token',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 0.99
  },
  // AWS Access Key ID
  {
    category: DetectionCategory.API_KEY,
    name: 'AWS Access Key ID',
    pattern: /\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
    severity: SensitivitySeverity.HIGH,
    confidence: 0.95
  },
  // Stripe API Key
  {
    category: DetectionCategory.API_KEY,
    name: 'Stripe Secret Key',
    pattern: /\b(?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34}\b/g,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 0.95
  },
  // Slack Token
  {
    category: DetectionCategory.API_KEY,
    name: 'Slack Bot / User Token',
    pattern: /\bxox(?:b|a|p|r|s)-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,32}\b/g,
    severity: SensitivitySeverity.HIGH,
    confidence: 0.95
  },
  // JSON Web Token (JWT)
  {
    category: DetectionCategory.JWT_TOKEN,
    name: 'JSON Web Token (JWT)',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    severity: SensitivitySeverity.HIGH,
    confidence: 0.90
  },
  // Database Connection URL with password
  {
    category: DetectionCategory.DATABASE_CREDENTIAL,
    name: 'Database URI with Embedded Password',
    pattern: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|mssql):\/\/[A-Za-z0-9_.-]+:[^@\s/]+@[A-Za-z0-9_.-]+(?::[0-9]+)?(?:\/[A-Za-z0-9_.-]*)?\b/g,
    severity: SensitivitySeverity.CRITICAL,
    confidence: 0.95
  }
];

export const PII_RULES: RegexRule[] = [
  // Email Address
  {
    category: DetectionCategory.EMAIL,
    name: 'Email Address',
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    severity: SensitivitySeverity.MEDIUM,
    confidence: 0.90
  },
  // Finnish Phone Numbers (+358 or 04x / 05x)
  {
    category: DetectionCategory.PHONE_NUMBER,
    name: 'Finnish Phone Number',
    // Require a numeric boundary on the left as well as on the right. The
    // extra two-character guard prevents matching a phone-looking suffix
    // after a digit separated by a space, for example inside a card or HETU.
    pattern: /(?<!\d)(?<!\d[ -])(?:\+358|0)(?:[ -]?\d{1,4}){1,3}[ -]?\d{4,8}(?![A-Za-z0-9])(?![ -/]\d)/g,
    severity: SensitivitySeverity.LOW,
    confidence: 0.85
  },
  // IPv4 Addresses (excluding standard localhost)
  {
    category: DetectionCategory.IP_ADDRESS,
    name: 'IPv4 Address',
    pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
    severity: SensitivitySeverity.LOW,
    confidence: 0.80
  }
];

