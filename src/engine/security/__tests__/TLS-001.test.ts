import { TLS_001 } from '../rules/TLS-001';
import { createMockRequest, createMockResponse } from './test-utils';

describe('TLS-001: HTTPS to HTTP fallback', () => {
  it('should flag an HTTPS redirect to HTTP', () => {
    const req = createMockRequest({ url: 'https://api.example.com/login' });
    const res = createMockResponse({
      statusCode: 302,
      headers: {
        'Location': 'http://api.example.com/home'
      }
    });

    const finding = TLS_001.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('TLS-001');
    expect(finding?.severity).toBe('high');
  });

  it('should not flag an HTTPS redirect to HTTPS', () => {
    const req = createMockRequest({ url: 'https://api.example.com/login' });
    const res = createMockResponse({
      statusCode: 302,
      headers: {
        'Location': 'https://api.example.com/dashboard'
      }
    });

    const finding = TLS_001.check(req, res);
    expect(finding).toBeNull();
  });

  it('should not flag an HTTP redirect to HTTP', () => {
    const req = createMockRequest({ url: 'http://api.example.com/v1' });
    const res = createMockResponse({
      statusCode: 301,
      headers: {
        'Location': 'http://api.example.com/v2'
      }
    });

    const finding = TLS_001.check(req, res);
    expect(finding).toBeNull();
  });

  it('should handle case-insensitive location header', () => {
    const req = createMockRequest({ url: 'https://api.example.com/' });
    const res = createMockResponse({
      statusCode: 307,
      headers: {
        'location': 'HTTP://api.example.com/insecure'
      }
    });

    const finding = TLS_001.check(req, res);
    expect(finding).not.toBeNull();
  });
});
