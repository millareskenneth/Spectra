import { SecurityRule, SecurityFinding } from '../../types';
import { getCookies, getCookieValue } from '../cookieUtils';

export const COK_003: SecurityRule = {
  id: 'COK-003',
  name: 'Cookie Missing "SameSite" Attribute',
  category: 'cookie',
  severity: 'medium',
  message: 'A cookie was set without the "SameSite" attribute.',
  recommendation: 'Add the "SameSite=Lax" or "SameSite=Strict" attribute to all cookies. This helps mitigate the risk of Cross-Site Request Forgery (CSRF).',
  check: (req, res): SecurityFinding | null => {
    const cookies = getCookies(res.headers);
    const missingSameSite: string[] = [];

    for (const cookie of cookies) {
      const sameSite = getCookieValue(cookie, 'SameSite');
      if (!sameSite) {
        const name = cookie.split('=')[0];
        missingSameSite.push(name);
      }
    }

    if (missingSameSite.length > 0) {
      return {
        ruleId: 'COK-003',
        severity: 'medium',
        category: 'cookie',
        name: 'Cookie Missing "SameSite" Attribute',
        message: `Cookie(s) [${missingSameSite.join(', ')}] missing "SameSite" attribute.`,
        evidence: `Missing SameSite in: ${missingSameSite.join(', ')}`,
        recommendation: 'Ensure all "Set-Cookie" headers include the "SameSite" attribute (Lax or Strict) to prevent CSRF attacks.',
      };
    }

    return null;
  }
};
