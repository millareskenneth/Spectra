import { SecurityRule, SecurityFinding } from '../../types';
import { maskValue } from '../masking';

const SENSITIVE_PARAMS = [
  'api_key', 'apikey', 'secret', 'token', 'access_token', 'auth_token', 
  'client_secret', 'app_secret', 'app_key', 'key'
];

export const REQ_001: SecurityRule = {
  id: 'REQ-001',
  name: 'API Key or Secret in URL',
  category: 'exposure',
  severity: 'critical',
  message: 'API keys or secrets should never be passed in URL query parameters.',
  recommendation: 'Move sensitive credentials to Request Headers (e.g., Authorization: Bearer <token>) or the request body.',
  check: (req, res): SecurityFinding | null => {
    try {
      const url = new URL(req.url);
      const params = url.searchParams;

      for (const param of SENSITIVE_PARAMS) {
        if (params.has(param)) {
          const value = params.get(param) || '';
          return {
            ruleId: 'REQ-001',
            severity: 'critical',
            category: 'exposure',
            name: 'API Key or Secret in URL',
            message: `Sensitive parameter "${param}" found in URL.`,
            evidence: `${param}=${maskValue(value)}`,
            recommendation: 'Move sensitive credentials to Request Headers.',
          };
        }
      }

      return null;
    } catch {
      return null;
    }
  }
};
