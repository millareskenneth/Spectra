import { SecurityRule, SecurityFinding } from '../../types';

export const HDR_005: SecurityRule = {
  id: 'HDR-005',
  name: 'Sensitive Header Disclosure',
  category: 'headers',
  severity: 'info',
  message: 'Headers like X-Powered-By or Server reveal details about the server stack.',
  recommendation: 'Remove headers that reveal server technology details to reduce the information available to potential attackers.',
  check: (req, res): SecurityFinding | null => {
    const xPoweredBy = res.headers['X-Powered-By'] || res.headers['x-powered-by'];
    const server = res.headers['Server'] || res.headers['server'];
    
    const findings: string[] = [];
    if (xPoweredBy) {
      findings.push(`X-Powered-By: ${xPoweredBy}`);
    }
    
    if (server) {
      findings.push(`Server: ${server}`);
    }

    if (findings.length > 0) {
      return {
        ruleId: 'HDR-005',
        severity: 'info',
        category: 'headers',
        name: 'Sensitive Header Disclosure',
        message: 'Headers revealing server stack details detected.',
        evidence: findings.join(', '),
        recommendation: 'Configure your server to suppress the "X-Powered-By" and "Server" headers to minimize information disclosure.',
      };
    }

    return null;
  }
};
