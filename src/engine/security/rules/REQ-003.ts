import { SecurityRule, SecurityFinding } from '../../types';
import { maskValue } from '../masking';

const AWS_ACCESS_KEY_REGEX = /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g;
// More specific regex for secret key to avoid false positives in long hashes
const AWS_SECRET_KEY_REGEX = /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g;

export const REQ_003: SecurityRule = {
  id: 'REQ-003',
  name: 'AWS Credentials Detected',
  category: 'exposure',
  severity: 'critical',
  message: 'AWS credentials (Access Key ID or Secret Access Key) detected in the request.',
  recommendation: 'Remove hardcoded AWS credentials. Use IAM roles or temporary credentials (STS).',
  check: (req, res): SecurityFinding | null => {
    const searchString = JSON.stringify({
      url: req.url,
      headers: req.headers,
      body: req.body
    });

    const accessKeyMatch = searchString.match(AWS_ACCESS_KEY_REGEX);
    if (accessKeyMatch) {
      return {
        ruleId: 'REQ-003',
        severity: 'critical',
        category: 'exposure',
        name: 'AWS Credentials Detected',
        message: 'AWS Access Key ID detected in request.',
        evidence: maskValue(accessKeyMatch[0]),
        recommendation: 'Revoke the compromised key and use IAM roles.',
      };
    }

    // Secret key is more prone to false positives, so we could be more careful,
    // but for this engine we'll flag it.
    const secretKeyMatch = searchString.match(AWS_SECRET_KEY_REGEX);
    if (secretKeyMatch) {
      // Basic heuristic: check if it looks like a hash (hex) vs base64
      // AWS Secret Keys use a wider alphabet than hex.
      const isHex = /^[0-9a-f]{40}$/i.test(secretKeyMatch[0]);
      if (!isHex) {
        return {
          ruleId: 'REQ-003',
          severity: 'critical',
          category: 'exposure',
          name: 'AWS Credentials Detected',
          message: 'AWS Secret Access Key pattern detected in request.',
          evidence: maskValue(secretKeyMatch[0]),
          recommendation: 'Revoke the compromised secret and use IAM roles.',
        };
      }
    }

    return null;
  }
};
