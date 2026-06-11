import { COK_001 } from '../rules/COK-001';
import { createMockRequest, createMockResponse } from './test-utils';

describe('COK-001: missing Secure flag', () => {
  const mockReq = createMockRequest();

  it('should flag a cookie missing Secure flag', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'sessionid=12345; HttpOnly'
      }
    });

    const finding = COK_001.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('sessionid');
  });

  it('should not flag a cookie with Secure flag', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'sessionid=12345; Secure; HttpOnly'
      }
    });

    const finding = COK_001.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should flag multiple cookies if any is missing Secure', () => {
    const res = createMockResponse({
      headers: {
        // Mocking multiple cookies joined by newline
        'Set-Cookie': 'a=1; Secure\nb=2'
      }
    });

    const finding = COK_001.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('b');
  });

  it('should handle case-insensitive Secure flag', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'id=abc; secure'
      }
    });

    const finding = COK_001.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
