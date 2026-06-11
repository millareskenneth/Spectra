import { COK_003 } from '../rules/COK-003';
import { createMockRequest, createMockResponse } from './test-utils';

describe('COK-003: missing SameSite attribute', () => {
  const mockReq = createMockRequest();

  it('should flag a cookie missing SameSite attribute', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'sessionid=12345; Secure; HttpOnly'
      }
    });

    const finding = COK_003.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('sessionid');
  });

  it('should not flag a cookie with SameSite=Lax', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'sessionid=12345; Secure; HttpOnly; SameSite=Lax'
      }
    });

    const finding = COK_003.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should not flag a cookie with SameSite=Strict', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'sessionid=12345; Secure; HttpOnly; SameSite=Strict'
      }
    });

    const finding = COK_003.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should flag multiple cookies if any is missing SameSite', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'a=1; SameSite=Lax\nb=2'
      }
    });

    const finding = COK_003.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('b');
  });

  it('should handle case-insensitive SameSite attribute', () => {
    const res = createMockResponse({
      headers: {
        'Set-Cookie': 'id=abc; samesite=none; Secure'
      }
    });

    const finding = COK_003.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
