import { SecurityRule, SecurityFinding } from '../../types';

export const HDR_003: SecurityRule = {
  id: 'HDR-003',
  name: 'Missing X-Content-Type-Options',
  category: 'headers',
  severity: 'low',
  message: 'The X-Content-Type-Options header is missing or not set to "nosniff".',
  recommendation: 'Add the "X-Content-Type-Options: nosniff" header to all responses to prevent browsers from MIME-sniffing.',
  check: (req, res): SecurityFinding | null => {
    const header = res.headers['X-Content-Type-Options'] || res.headers['x-content-type-options'];

    if (!header || header.toLowerCase() !== 'nosniff') {
      return {
        ruleId: 'HDR-003',
        severity: 'low',
        category: 'headers',
        name: 'Missing X-Content-Type-Options',
        message: 'X-Content-Type-Options header is missing or misconfigured.',
        evidence: header ? `Current value: ${header}` : 'Header missing',
        recommendation: 'Add "X-Content-Type-Options: nosniff" to your server response headers.',
      };
    }

    return null;
  }
};
