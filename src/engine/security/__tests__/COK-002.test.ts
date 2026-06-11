import { COK_002 } from '../rules/COK-002';
import { createMockRequest, createMockResponse } from './test-utils';

describe('COK-002: missing HttpOnly flag', () => {
  const mockReq = createMockRequest();

  it('should flag a cookie missing HttpOnly flag', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'sessionid=12345; Secure'
      }
    });

    const finding = COK_002.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('sessionid');
  });

  it('should not flag a cookie with HttpOnly flag', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'sessionid=12345; Secure; HttpOnly'
      }
    });

    const finding = COK_002.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should flag multiple cookies if any is missing HttpOnly', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'a=1; HttpOnly\nb=2'
      }
    });

    const finding = COK_002.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('b');
  });

  it('should handle case-insensitive HttpOnly flag', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'id=abc; httponly'
      }
    });

    const finding = COK_002.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
