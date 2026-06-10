import { SecurityRule, SecurityFinding } from '../../types';
import { maskValue } from '../masking';

const PII_PATTERNS = [
  { name: 'Social Security Number (SSN)', regex: /\b\d{3}-\d{2}-\d{4}\b/g },
  { name: 'Credit Card Number', regex: /\b(?:\d[ -]*?){13,16}\b/g }, // Basic Luhn check not included for performance
  { name: 'Phone Number (US)', regex: /\b(?:\+?1[-. ]?)?\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})\b/g },
  { name: 'Email Address', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g }
];

export const RES_004: SecurityRule = {
  id: 'RES-004',
  name: 'Excessive PII in Response',
  category: 'data-leak',
  severity: 'high',
  message: 'Responses should not contain excessive Personal Identifiable Information (PII).',
  recommendation: 'Minimize the amount of PII returned in API responses. Use masking or tokenization for sensitive data.',
  check: (req, res): SecurityFinding | null => {
    if (!res.body) {
      return null;
    }

    const foundPII: string[] = [];

    for (const pattern of PII_PATTERNS) {
      const matches = res.body.match(pattern.regex);
      if (matches) {
        // Avoid flagging common false positives like dates or version numbers if possible
        // For this engine, we'll flag and let the user decide
        foundPII.push(pattern.name);
      }
    }

    if (foundPII.length > 0) {
      return {
        ruleId: 'RES-004',
        severity: 'high',
        category: 'data-leak',
        name: 'Excessive PII in Response',
        message: `PII types [${foundPII.join(', ')}] detected in response body.`,
        evidence: `Detected: ${foundPII.join(', ')}`,
        recommendation: 'Ensure only necessary PII is returned and sensitive values are masked.',
      };
    }

    return null;
  }
};
