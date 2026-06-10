import { SecurityRule, SecurityFinding } from '../../types';

const STACK_TRACE_PATTERNS = [
  /at\s+.*\s+\(.*\.[a-z]+:[0-9]+:[0-9]+\)/i, // JS stack trace
  /at\s+.*:[0-9]+:[0-9]+/i,                   // Generic stack trace
  /File\s+".*",\s+line\s+[0-9]+,\s+in\s+.*/i, // Python stack trace
  /\.java:[0-9]+/i,                           // Java stack trace
  /\.php:[0-9]+/i                             // PHP stack trace
];

export const RES_001: SecurityRule = {
  id: 'RES-001',
  name: 'Stack Trace Exposure',
  category: 'data-leak',
  severity: 'high',
  message: 'Stack traces should not be exposed in production responses.',
  recommendation: 'Disable detailed error messages in production. Return generic error messages to the client.',
  check: (req, res): SecurityFinding | null => {
    if (!res.body) {
      return null;
    }

    for (const pattern of STACK_TRACE_PATTERNS) {
      if (pattern.test(res.body)) {
        return {
          ruleId: 'RES-001',
          severity: 'high',
          category: 'data-leak',
          name: 'Stack Trace Exposure',
          message: 'Potential stack trace detected in response body.',
          evidence: 'Stack trace pattern found in body.',
          recommendation: 'Ensure your server does not expose internal stack traces in production.',
        };
      }
    }

    if (res.body.includes('Stack trace:') || res.body.includes('Caused by:')) {
      return {
        ruleId: 'RES-001',
        severity: 'high',
        category: 'data-leak',
        name: 'Stack Trace Exposure',
        message: 'Explicit stack trace label detected in response body.',
        evidence: 'Explicit error trace labels found in body.',
        recommendation: 'Ensure your server does not expose internal stack traces in production.',
      };
    }

    return null;
  }
};
