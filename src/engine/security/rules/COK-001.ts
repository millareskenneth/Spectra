import { SecurityRule, SecurityFinding } from '../../types';
import { getCookies, hasCookieFlag } from '../cookieUtils';

export const COK_001: SecurityRule = {
  id: 'COK-001',
  name: 'Cookie Missing "Secure" Flag',
  category: 'cookie',
  severity: 'high',
  message: 'A cookie was set without the "Secure" flag.',
  recommendation: 'Add the "Secure" flag to all cookies. This ensures the cookie is only sent over encrypted (HTTPS) connections.',
  check: (req, res): SecurityFinding | null => {
    const cookies = getCookies(res.headers);
    const missingSecure: string[] = [];

    for (const cookie of cookies) {
      if (!hasCookieFlag(cookie, 'Secure')) {
        const name = cookie.split('=')[0];
        missingSecure.push(name);
      }
    }

    if (missingSecure.length > 0) {
      return {
        ruleId: 'COK-001',
        severity: 'high',
        category: 'cookie',
        name: 'Cookie Missing "Secure" Flag',
        message: `Cookie(s) [${missingSecure.join(', ')}] missing "Secure" flag.`,
        evidence: `Missing Secure flag in: ${missingSecure.join(', ')}`,
        recommendation: 'Ensure all "Set-Cookie" headers include the "Secure" attribute to prevent transmission over plain HTTP.',
      };
    }

    return null;
  }
};
