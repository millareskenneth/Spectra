import { SecurityRule, SecurityFinding } from '../../types';

export const HDR_002: SecurityRule = {
  id: 'HDR-002',
  name: 'Missing Content-Security-Policy',
  category: 'headers',
  severity: 'medium',
  message: 'The Content-Security-Policy (CSP) header is missing from the HTML response.',
  recommendation: 'Implement a strong Content-Security-Policy to mitigate Cross-Site Scripting (XSS) and other injection attacks.',
  check: (req, res): SecurityFinding | null => {
    const contentType = res.headers['Content-Type'] || res.headers['content-type'] || '';
    
    // CSP is primarily relevant for HTML content
    if (!contentType.toLowerCase().includes('text/html')) {
      return null;
    }

    const cspHeader = res.headers['Content-Security-Policy'] || res.headers['content-security-policy'];

    if (!cspHeader) {
      return {
        ruleId: 'HDR-002',
        severity: 'medium',
        category: 'headers',
        name: 'Missing Content-Security-Policy',
        message: 'Content-Security-Policy header is missing from HTML response.',
        evidence: `Content-Type: ${contentType}`,
        recommendation: 'Add a "Content-Security-Policy" header. Start with a restrictive policy like "default-src \'self\';" and expand as needed.',
      };
    }

    return null;
  }
};
