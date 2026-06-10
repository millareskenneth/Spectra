import { SecurityRule, SecurityFinding } from '../../types';

export const REQ_004: SecurityRule = {
  id: 'REQ-004',
  name: 'Authorization Token over HTTP',
  category: 'transport',
  severity: 'critical',
  message: 'Authorization tokens should never be sent over plain HTTP.',
  recommendation: 'Use HTTPS for all requests that include sensitive authorization tokens.',
  check: (req, res): SecurityFinding | null => {
    // Only flag if it's explicitly plain HTTP
    if (!req.url.toLowerCase().startsWith('http://')) {
      return null;
    }

    const authHeaders = ['authorization', 'x-api-key', 'x-access-token', 'session-id', 'cookie'];
    const foundHeader = Object.keys(req.headers).find(h => authHeaders.includes(h.toLowerCase()));

    if (foundHeader) {
      return {
        ruleId: 'REQ-004',
        severity: 'critical',
        category: 'transport',
        name: 'Authorization Token over HTTP',
        message: `Sensitive header "${foundHeader}" sent over unencrypted HTTP.`,
        evidence: `URL: ${req.url.split('?')[0]}, Header: ${foundHeader}`,
        recommendation: 'Ensure the endpoint uses HTTPS.',
      };
    }

    return null;
  }
};
