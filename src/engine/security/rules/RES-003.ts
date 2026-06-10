import { SecurityRule, SecurityFinding } from '../../types';

const AUTH_ENDPOINTS = ['/login', '/signin', '/signup', '/register', '/auth'];
const SENSITIVE_FIELDS = ['password', 'pwd', 'passphrase', 'secret_phrase', 'credential', 'hashed_password', 'salt'];

export const RES_003: SecurityRule = {
  id: 'RES-003',
  name: 'Sensitive Fields in Auth Response',
  category: 'data-leak',
  severity: 'critical',
  message: 'Authentication endpoints should never return sensitive fields like passwords or salts in the response body.',
  recommendation: 'Filter the user object before returning it in the response. Ensure sensitive fields are excluded from JSON serialization.',
  check: (req, res): SecurityFinding | null => {
    // 1. Heuristic: Is this an auth-related endpoint?
    const url = req.url.toLowerCase();
    const isAuthEndpoint = AUTH_ENDPOINTS.some(endpoint => url.includes(endpoint));

    if (!isAuthEndpoint || !res.body) {
      return null;
    }

    try {
      const body = JSON.parse(res.body);
      
      // Recursive function to search for sensitive keys in nested objects
      const findSensitiveKeys = (obj: any): string[] => {
        const found: string[] = [];
        if (typeof obj !== 'object' || obj === null) return found;

        for (const key in obj) {
          if (SENSITIVE_FIELDS.includes(key.toLowerCase())) {
            found.push(key);
          }
          if (typeof obj[key] === 'object') {
            found.push(...findSensitiveKeys(obj[key]));
          }
        }
        return found;
      };

      const leakedKeys = findSensitiveKeys(body);

      if (leakedKeys.length > 0) {
        return {
          ruleId: 'RES-003',
          severity: 'critical',
          category: 'data-leak',
          name: 'Sensitive Fields in Auth Response',
          message: `Sensitive field(s) [${leakedKeys.join(', ')}] detected in authentication response.`,
          evidence: `Fields found: ${leakedKeys.join(', ')}`,
          recommendation: 'Remove sensitive fields from the response payload.',
        };
      }
    } catch {
      // If body isn't JSON, we might still want to check for raw strings, 
      // but usually these are JSON APIs.
      for (const field of SENSITIVE_FIELDS) {
        if (res.body.toLowerCase().includes(`"${field}"`)) {
          return {
            ruleId: 'RES-003',
            severity: 'critical',
            category: 'data-leak',
            name: 'Sensitive Fields in Auth Response',
            message: `Potential sensitive field "${field}" detected in raw response.`,
            evidence: field,
            recommendation: 'Remove sensitive fields from the response payload.',
          };
        }
      }
    }

    return null;
  }
};
