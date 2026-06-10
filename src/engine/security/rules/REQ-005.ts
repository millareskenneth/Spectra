import { SecurityRule, SecurityFinding } from '../../types';
import { maskValue } from '../masking';

const PRIVATE_KEY_PATTERNS = [
  '-----BEGIN RSA PRIVATE KEY-----',
  '-----BEGIN PRIVATE KEY-----',
  '-----BEGIN EC PRIVATE KEY-----',
  '-----BEGIN OPENSSH PRIVATE KEY-----',
  '-----BEGIN DSA PRIVATE KEY-----',
  '-----BEGIN PGP PRIVATE KEY BLOCK-----'
];

export const REQ_005: SecurityRule = {
  id: 'REQ-005',
  name: 'Private Key in Request Body',
  category: 'exposure',
  severity: 'critical',
  message: 'Private keys should never be sent in the request body.',
  recommendation: 'Ensure private keys are kept secure and never transmitted in request payloads.',
  check: (req, res): SecurityFinding | null => {
    if (!req.body) {
      return null;
    }

    for (const pattern of PRIVATE_KEY_PATTERNS) {
      if (req.body.includes(pattern)) {
        return {
          ruleId: 'REQ-005',
          severity: 'critical',
          category: 'exposure',
          name: 'Private Key in Request Body',
          message: `Private key pattern ("${pattern}") detected in request body.`,
          evidence: pattern, // We only show the header as evidence
          recommendation: 'Revoke the compromised key and use a secure vault or enclave.',
        };
      }
    }

    return null;
  }
};
