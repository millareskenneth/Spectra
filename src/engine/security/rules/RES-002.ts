import { SecurityRule, SecurityFinding } from '../../types';

const PATH_PATTERNS = [
  // Linux/Unix absolute paths
  /(?:\/home\/[a-z0-9_-]+(?:\/[a-z0-9._-]+)*)/i,
  /(?:\/var\/www\/[a-z0-9_-]+(?:\/[a-z0-9._-]+)*)/i,
  /(?:\/etc\/(?:passwd|shadow|group|config))/i,
  // Windows absolute paths (greedy)
  /(?:[a-z]:\\(?:Users|Windows|Program Files|AppData)(?:\\[a-z0-9._-]+)*)/i,
  // Generic suspicious patterns (often found in stack traces or error logs)
  /([a-z0-9_-]+\/){3,}[a-z0-9_-]+\.[a-z0-9]{2,4}/i
];

export const RES_002: SecurityRule = {
  id: 'RES-002',
  name: 'Internal Server Path Exposure',
  category: 'data-leak',
  severity: 'medium',
  message: 'Internal server paths should not be exposed in response bodies.',
  recommendation: 'Sanitize error messages and logs to remove absolute file system paths before sending them to the client.',
  check: (req, res): SecurityFinding | null => {
    if (!res.body) {
      return null;
    }

    for (const pattern of PATH_PATTERNS) {
      const match = res.body.match(pattern);
      if (match) {
        return {
          ruleId: 'RES-002',
          severity: 'medium',
          category: 'data-leak',
          name: 'Internal Server Path Exposure',
          message: `Potential internal server path "${match[0]}" detected in response body.`,
          evidence: match[0],
          recommendation: 'Remove absolute file paths from the response.',
        };
      }
    }

    return null;
  }
};
