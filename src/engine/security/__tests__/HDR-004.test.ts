import { HDR_004 } from '../rules/HDR-004';
import { createMockRequest, createMockResponse } from './test-utils';

describe('HDR-004: Missing X-Frame-Options', () => {
  const mockReq = createMockRequest();

  it('should flag missing XFO on HTML response', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'text/html'
      }
    });

    const finding = HDR_004.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('HDR-004');
  });

  it('should not flag missing XFO on JSON response', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const finding = HDR_004.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should not flag when XFO is present', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'text/html',
        'X-Frame-Options': 'SAMEORIGIN'
      }
    });

    const finding = HDR_004.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should not flag when CSP frame-ancestors is present', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'text/html',
        'Content-Security-Policy': "frame-ancestors 'self'"
      }
    });

    const finding = HDR_004.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should handle case-insensitivity', () => {
    const res = createMockResponse({
      headers: {
        'content-type': 'text/html',
        'x-frame-options': 'DENY'
      }
    });

    const finding = HDR_004.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
