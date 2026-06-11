import { SecurityRule, SecurityFinding } from '../../types';

export const TLS_001: SecurityRule = {
  id: 'TLS-001',
  name: 'HTTPS to HTTP Fallback Redirect',
  category: 'transport',
  severity: 'high',
  message: 'A secure HTTPS endpoint redirected to an insecure HTTP URL.',
  recommendation: 'Ensure all redirects from secure endpoints point to other secure (HTTPS) URLs. Insecure redirects can expose sensitive tokens or session data during the transition.',
  check: (req, res): SecurityFinding | null => {
    // Only check if the original request was HTTPS
    if (!req.url.startsWith('https://')) {
      return null;
    }

    // Check if it's a redirect status code (3xx)
    if (res.statusCode >= 300 && res.statusCode < 400) {
      const location = res.headers['Location'] || res.headers['location'];
      
      // If redirect location exists and starts with http:// (unencrypted)
      if (location && location.toLowerCase().startsWith('http://')) {
        return {
          ruleId: 'TLS-001',
          severity: 'high',
          category: 'transport',
          name: 'HTTPS to HTTP Fallback Redirect',
          message: 'Insecure redirect from HTTPS to HTTP detected.',
          evidence: `Redirected to: ${location}`,
          recommendation: 'Update your server configuration or application logic to always redirect to HTTPS endpoints.',
        };
      }
    }

    return null;
  }
};
