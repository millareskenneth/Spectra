import { SecurityRule, SecurityFinding } from '../../types';

export const TLS_002: SecurityRule = {
  id: 'TLS-002',
  name: 'Certificate Pinning Detected',
  category: 'transport',
  severity: 'info',
  message: 'The client application appears to be using certificate pinning, as it rejected the proxy certificate.',
  recommendation: 'Certificate pinning is a security feature that prevents interception. To inspect traffic for this app, you may need to use a pinning bypass tool (like Frida or a patched APK) on a rooted device.',
  check: (req, res): SecurityFinding | null => {
    /**
     * In the context of MobileGuard, pinning is usually detected at the engine level 
     * (e.g., when the TLS handshake fails because the client closes the connection).
     * However, for the rule engine, we might flag it if we see a 0 status code or a specific 
     * error indicator in the capture metadata (if the engine provides it).
     * 
     * Since CapturedResponse currently doesn't have an error field, we'll look for 
     * statusCode 0 (common indicator for connection failure in many proxy engines).
     */
    if (res.statusCode === 0) {
      return {
        ruleId: 'TLS-002',
        severity: 'info',
        category: 'transport',
        name: 'Certificate Pinning Detected',
        message: 'Potential certificate pinning detected (Connection rejected by client).',
        evidence: `StatusCode: ${res.statusCode}`,
        recommendation: 'Check if the target app uses certificate pinning. If so, standard interception will fail unless pinning is bypassed on the device.',
      };
    }

    return null;
  }
};
