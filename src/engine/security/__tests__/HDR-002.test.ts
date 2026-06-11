import { HDR_002 } from '../rules/HDR-002';
import { createMockRequest, createMockResponse } from './test-utils';

describe('HDR-002: Missing Content-Security-Policy', () => {
  const mockReq = createMockRequest();

  it('should flag missing CSP on HTML response', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'text/html; charset=utf-8'
      }
    });

    const finding = HDR_002.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('HDR-002');
  });

  it('should not flag missing CSP on JSON response', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const finding = HDR_002.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should not flag when CSP header is present', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'text/html',
        'Content-Security-Policy': "default-src 'self'"
      }
    });

    const finding = HDR_002.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should handle case-insensitive headers', () => {
    const res = createMockResponse({
      headers: {
        'content-type': 'TEXT/HTML',
        'content-security-policy': "default-src 'none'"
      }
    });

    const finding = HDR_002.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
