import { SecurityRule, SecurityFinding } from '../../types';
import { extractJWTs, decodeJWTPayload } from '../jwtUtils';

const SENSITIVE_JWT_FIELDS = [
  'ssn', 'social_security', 'birthdate', 'dob', 
  'credit_card', 'cc', 'address', 'phone_number', 
  'password', 'pwd', 'hashed_password', 'salt'
];

export const JWT_003: SecurityRule = {
  id: 'JWT-003',
  name: 'Sensitive PII in JWT Payload',
  category: 'jwt',
  severity: 'high',
  message: 'A JSON Web Token (JWT) containing sensitive personal information in its payload was detected.',
  recommendation: 'Avoid storing sensitive PII in JWT payloads, as they are only base64-encoded and can be easily decoded by anyone with access to the token. Store only non-sensitive user identifiers.',
  check: (req, res): SecurityFinding | null => {
    const allHeaders = { ...req.headers, ...res.headers };
    const tokens = extractJWTs(allHeaders);

    for (const token of tokens) {
      const payload = decodeJWTPayload(token);
      if (payload && typeof payload === 'object') {
        const foundFields: string[] = [];
        
        const checkFields = (obj: any) => {
          if (typeof obj !== 'object' || obj === null) return;
          for (const key in obj) {
            if (SENSITIVE_JWT_FIELDS.includes(key.toLowerCase())) {
              foundFields.push(key);
            }
            if (typeof obj[key] === 'object') {
              checkFields(obj[key]);
            }
          }
        };

        checkFields(payload);

        if (foundFields.length > 0) {
          return {
            ruleId: 'JWT-003',
            severity: 'high',
            category: 'jwt',
            name: 'Sensitive PII in JWT Payload',
            message: `Sensitive PII field(s) [${foundFields.join(', ')}] detected in JWT payload.`,
            evidence: `Found fields: ${foundFields.join(', ')}`,
            recommendation: 'Remove sensitive PII from JWT payloads. Tokens are readable by the client and any interceptors.',
          };
        }
      }
    }

    return null;
  }
};
