import { HDR_001 } from '../rules/HDR-001';
import { createMockRequest, createMockResponse } from './test-utils';

describe('HDR-001: Missing HSTS Header', () => {
  it('should flag missing HSTS on HTTPS request', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1' });
    const res = createMockResponse({
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const finding = HDR_001.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('HDR-001');
  });

  it('should not flag missing HSTS on HTTP request', () => {
    const req = createMockRequest({ url: 'http://api.example.com/v1' });
    const res = createMockResponse({
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const finding = HDR_001.check(req, res);
    expect(finding).toBeNull();
  });

  it('should not flag when HSTS header is present (case-insensitive)', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1' });
    const res = createMockResponse({
      headers: {
        'strict-transport-security': 'max-age=31536000'
      }
    });

    const finding = HDR_001.check(req, res);
    expect(finding).toBeNull();
  });

  it('should not flag when HSTS header is present (standard case)', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1' });
    const res = createMockResponse({
      headers: {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
      }
    });

    const finding = HDR_001.check(req, res);
    expect(finding).toBeNull();
  });
});
