import { SecurityRule, SecurityFinding } from '../../types';

/**
 * Extracts potential JWTs from headers.
 * Looks for the common pattern 'ey...' (base64 for '{' or '[' which starts most JWT headers/payloads)
 */
function extractJWTs(headers: Record<string, string>): string[] {
  const tokens: string[] = [];
  // JWT regex: header.payload.signature (all base64url)
  const jwtPattern = /ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;

  for (const value of Object.values(headers)) {
    const matches = value.match(jwtPattern);
    if (matches) {
      tokens.push(...matches);
    }
  }

  return tokens;
}

function decodeJWTHeader(token: string): any | null {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    
    // Convert base64url to base64
    let base64 = parts[0].replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    
    const headerJson = Buffer.from(base64, 'base64').toString();
    return JSON.parse(headerJson);
  } catch {
    return null;
  }
}

export const JWT_001: SecurityRule = {
  id: 'JWT-001',
  name: 'JWT with "alg: none"',
  category: 'jwt',
  severity: 'critical',
  message: 'A JSON Web Token (JWT) using the "none" algorithm was detected.',
  recommendation: 'Ensure your JWT implementation rejects tokens with "alg: none". Use strong cryptographic algorithms like RS256 or HS256 and always verify the signature.',
  check: (req, res): SecurityFinding | null => {
    const allHeaders = { ...req.headers, ...res.headers };
    const tokens = extractJWTs(allHeaders);

    for (const token of tokens) {
      const header = decodeJWTHeader(token);
      if (header && header.alg && header.alg.toLowerCase() === 'none') {
        return {
          ruleId: 'JWT-001',
          severity: 'critical',
          category: 'jwt',
          name: 'JWT with "alg: none"',
          message: 'JWT "alg: none" vulnerability detected.',
          evidence: `Token header: ${JSON.stringify(header)}`,
          recommendation: 'Reject JWTs with "alg: none" on the server. Update your JWT library and configuration to enforce strong signing algorithms.',
        };
      }
    }

    return null;
  }
};
