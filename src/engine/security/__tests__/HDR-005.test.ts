import { HDR_005 } from '../rules/HDR-005';
import { createMockRequest, createMockResponse } from './test-utils';

describe('HDR-005: Sensitive Header Disclosure', () => {
  const mockReq = createMockRequest();

  it('should flag X-Powered-By header', () => {
    const res = createMockResponse({
      headers: {
        'X-Powered-By': 'PHP/7.4.3'
      }
    });

    const finding = HDR_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.severity).toBe('info');
    expect(finding?.evidence).toContain('X-Powered-By: PHP/7.4.3');
  });

  it('should flag Server header', () => {
    const res = createMockResponse({
      headers: {
        'Server': 'Apache'
      }
    });

    const finding = HDR_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('Server: Apache');
  });

  it('should flag both headers when present', () => {
    const res = createMockResponse({
      headers: {
        'Server': 'nginx',
        'X-Powered-By': 'Express'
      }
    });

    const finding = HDR_005.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('Server: nginx');
    expect(finding?.evidence).toContain('X-Powered-By: Express');
  });

  it('should not flag when headers are missing', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const finding = HDR_005.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
