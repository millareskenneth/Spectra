import { SecurityRule, SecurityFinding } from '../../types';
import { getCookies, hasCookieFlag } from '../cookieUtils';

export const COK_002: SecurityRule = {
  id: 'COK-002',
  name: 'Cookie Missing "HttpOnly" Flag',
  category: 'cookie',
  severity: 'high',
  message: 'A cookie was set without the "HttpOnly" flag.',
  recommendation: 'Add the "HttpOnly" flag to all sensitive cookies. This prevents client-side scripts from accessing the cookie, mitigating the risk of session theft via Cross-Site Scripting (XSS).',
  check: (req, res): SecurityFinding | null => {
    const cookies = getCookies(res.headers);
    const missingHttpOnly: string[] = [];

    for (const cookie of cookies) {
      if (!hasCookieFlag(cookie, 'HttpOnly')) {
        const name = cookie.split('=')[0];
        missingHttpOnly.push(name);
      }
    }

    if (missingHttpOnly.length > 0) {
      return {
        ruleId: 'COK-002',
        severity: 'high',
        category: 'cookie',
        name: 'Cookie Missing "HttpOnly" Flag',
        message: `Cookie(s) [${missingHttpOnly.join(', ')}] missing "HttpOnly" flag.`,
        evidence: `Missing HttpOnly flag in: ${missingHttpOnly.join(', ')}`,
        recommendation: 'Ensure all "Set-Cookie" headers include the "HttpOnly" attribute for sensitive data.',
      };
    }

    return null;
  }
};
