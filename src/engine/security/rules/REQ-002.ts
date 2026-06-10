import { SecurityRule, SecurityFinding } from '../../types';
import { maskValue } from '../masking';

const PASSWORD_PARAMS = [
  'password', 'pwd', 'pass', 'passphrase', 'secret_phrase', 'credential'
];

export const REQ_002: SecurityRule = {
  id: 'REQ-002',
  name: 'Password in URL',
  category: 'exposure',
  severity: 'critical',
  message: 'Passwords should never be passed in URL query parameters.',
  recommendation: 'Move passwords to the request body, preferably as part of a JSON payload over a secure HTTPS connection.',
  check: (req, res): SecurityFinding | null => {
    try {
      const url = new URL(req.url);
      const params = url.searchParams;

      for (const param of PASSWORD_PARAMS) {
        if (params.has(param)) {
          const value = params.get(param) || '';
          return {
            ruleId: 'REQ-002',
            severity: 'critical',
            category: 'exposure',
            name: 'Password in URL',
            message: `Sensitive parameter "${param}" found in URL.`,
            evidence: `${param}=${maskValue(value)}`,
            recommendation: 'Move passwords to the request body.',
          };
        }
      }

      return null;
    } catch {
      return null;
    }
  }
};
