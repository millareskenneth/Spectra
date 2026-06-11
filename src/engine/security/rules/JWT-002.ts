import { SecurityRule, SecurityFinding } from '../../types';
import { extractJWTs, decodeJWTPayload } from '../jwtUtils';

export const JWT_002: SecurityRule = {
  id: 'JWT-002',
  name: 'JWT Missing "exp" Claim',
  category: 'jwt',
  severity: 'high',
  message: 'A JSON Web Token (JWT) missing the expiration ("exp") claim was detected.',
  recommendation: 'Always include an "exp" (expiration) claim in JWTs to limit their lifetime and reduce the window of opportunity for token reuse if compromised.',
  check: (req, res): SecurityFinding | null => {
    const allHeaders = { ...req.headers, ...res.headers };
    const tokens = extractJWTs(allHeaders);

    for (const token of tokens) {
      const payload = decodeJWTPayload(token);
      // Ensure it's a valid object and lacks 'exp'
      if (payload && typeof payload === 'object' && !payload.exp) {
        return {
          ruleId: 'JWT-002',
          severity: 'high',
          category: 'jwt',
          name: 'JWT Missing "exp" Claim',
          message: 'JWT missing expiration claim detected.',
          evidence: `Payload: ${JSON.stringify(payload)}`,
          recommendation: 'Configure your JWT provider to include a short-lived "exp" claim in all tokens.',
        };
      }
    }

    return null;
  }
};
