import { SecurityRule, SecurityFinding } from '../../types';
import { extractJWTs } from '../jwtUtils';

export const JWT_004: SecurityRule = {
  id: 'JWT-004',
  name: 'JWT Sent Over Plain HTTP',
  category: 'jwt',
  severity: 'critical',
  message: 'A JSON Web Token (JWT) was detected in a request or response sent over unencrypted HTTP.',
  recommendation: 'Always use HTTPS for any communication that involves authentication tokens. Plain HTTP allows attackers to easily intercept tokens via Man-in-the-Middle (MitM) attacks.',
  check: (req, res): SecurityFinding | null => {
    // Only applies if NOT using HTTPS
    if (req.url.startsWith('https://')) {
      return null;
    }

    const allHeaders = { ...req.headers, ...res.headers };
    const tokens = extractJWTs(allHeaders);

    if (tokens.length > 0) {
      return {
        ruleId: 'JWT-004',
        severity: 'critical',
        category: 'jwt',
        name: 'JWT Sent Over Plain HTTP',
        message: 'Authentication token (JWT) detected over unencrypted connection.',
        evidence: `URL: ${req.url}`,
        recommendation: 'Enforce HTTPS for all API endpoints and ensure tokens are never transmitted over plain HTTP.',
      };
    }

    return null;
  }
};
