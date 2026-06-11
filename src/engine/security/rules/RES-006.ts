import { SecurityRule, SecurityFinding } from '../../types';

const FINGERPRINT_HEADERS = [
  { name: 'X-Powered-By', pattern: /.+/i },
  { name: 'Server', pattern: /[a-zA-Z]+\/[0-9.]+/i }, // Specifically looking for version numbers
  { name: 'X-AspNet-Version', pattern: /.+/i },
  { name: 'X-Generator', pattern: /.+/i },
  { name: 'X-Runtime', pattern: /.+/i },
  { name: 'X-Varnish', pattern: /.+/i },
  { name: 'X-Version', pattern: /.+/i }
];

const BODY_FINGERPRINTS = [
  { name: 'WordPress', regex: /<meta name="generator" content="WordPress [0-9.]+/i },
  { name: 'Drupal', regex: /<meta name="Generator" content="Drupal [0-9.]+/i },
  { name: 'Joomla', regex: /<meta name="generator" content="Joomla!/i },
  { name: 'Express.js', regex: /Error:.*at.*node_modules\/express/i },
  { name: 'Next.js', regex: /"__NEXT_DATA__"/i }
];

export const RES_006: SecurityRule = {
  id: 'RES-006',
  name: 'Server Technology Fingerprint',
  category: 'data-leak',
  severity: 'medium',
  message: 'The server reveals specific technology versions or stack details in headers or response body.',
  recommendation: 'Remove or obfuscate headers that reveal specific server technologies and version numbers (e.g., X-Powered-By, Server). Disable version strings in meta tags.',
  check: (req, res): SecurityFinding | null => {
    const findings: string[] = [];

    // 1. Check Headers
    for (const { name, pattern } of FINGERPRINT_HEADERS) {
      const headerValue = res.headers[name] || res.headers[name.toLowerCase()];
      if (headerValue && pattern.test(headerValue)) {
        findings.push(`Header "${name}: ${headerValue}"`);
      }
    }

    // 2. Check Body
    if (res.body) {
      for (const { name, regex } of BODY_FINGERPRINTS) {
        if (regex.test(res.body)) {
          findings.push(`Body pattern for ${name}`);
        }
      }
    }

    if (findings.length > 0) {
      return {
        ruleId: 'RES-006',
        severity: 'medium',
        category: 'data-leak',
        name: 'Server Technology Fingerprint',
        message: `Server technology fingerprint detected: ${findings[0]}`,
        evidence: findings.join('; '),
        recommendation: 'Ensure your server does not expose internal stack details or specific version numbers in responses.',
      };
    }

    return null;
  }
};
