import { SecurityRule, SecurityFinding } from '../../types';

export const HDR_001: SecurityRule = {
  id: 'HDR-001',
  name: 'Missing HSTS Header',
  category: 'headers',
  severity: 'medium',
  message: 'The Strict-Transport-Security (HSTS) header is missing from the HTTPS response.',
  recommendation: 'Enable HSTS on your server by adding the "Strict-Transport-Security" header. This ensures that the browser only communicates with your server over HTTPS.',
  check: (req, res): SecurityFinding | null => {
    // HSTS is only applicable over HTTPS
    if (!req.url.startsWith('https://')) {
      return null;
    }

    const hstsHeader = res.headers['Strict-Transport-Security'] || res.headers['strict-transport-security'];

    if (!hstsHeader) {
      return {
        ruleId: 'HDR-001',
        severity: 'medium',
        category: 'headers',
        name: 'Missing HSTS Header',
        message: 'Strict-Transport-Security header is missing from HTTPS response.',
        evidence: 'No HSTS header found in response headers.',
        recommendation: 'Add the "Strict-Transport-Security" header with a reasonable max-age (e.g., 31536000) and consider including "includeSubDomains".',
      };
    }

    return null;
  }
};
