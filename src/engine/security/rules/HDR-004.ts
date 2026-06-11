import { SecurityRule, SecurityFinding } from '../../types';

export const HDR_004: SecurityRule = {
  id: 'HDR-004',
  name: 'Missing X-Frame-Options',
  category: 'headers',
  severity: 'low',
  message: 'The X-Frame-Options header is missing from the HTML response, which can lead to clickjacking attacks.',
  recommendation: 'Add the "X-Frame-Options: DENY" or "X-Frame-Options: SAMEORIGIN" header to your HTML responses. Alternatively, use the "frame-ancestors" directive in your Content-Security-Policy.',
  check: (req, res): SecurityFinding | null => {
    const contentType = res.headers['Content-Type'] || res.headers['content-type'] || '';
    
    if (!contentType.toLowerCase().includes('text/html')) {
      return null;
    }

    const xfo = res.headers['X-Frame-Options'] || res.headers['x-frame-options'];
    const csp = res.headers['Content-Security-Policy'] || res.headers['content-security-policy'] || '';

    const hasCSPFrameAncestors = csp.includes('frame-ancestors');

    if (!xfo && !hasCSPFrameAncestors) {
      return {
        ruleId: 'HDR-004',
        severity: 'low',
        category: 'headers',
        name: 'Missing X-Frame-Options',
        message: 'Clickjacking protection header (X-Frame-Options or CSP frame-ancestors) is missing.',
        evidence: `Content-Type: ${contentType}`,
        recommendation: 'Implement "X-Frame-Options: SAMEORIGIN" or a CSP "frame-ancestors" policy to prevent clickjacking.',
      };
    }

    return null;
  }
};
