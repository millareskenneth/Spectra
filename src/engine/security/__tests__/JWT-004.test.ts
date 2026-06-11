import { JWT_004 } from '../rules/JWT-004';
import { createMockRequest, createMockResponse } from './test-utils';

describe('JWT-004: sent over plain HTTP', () => {
  const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  it('should flag JWT over HTTP request', () => {
    const req = createMockRequest({ 
        url: 'http://api.example.com/login',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_004.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.severity).toBe('critical');
  });

  it('should flag JWT in response over HTTP', () => {
    const req = createMockRequest({ url: 'http://api.example.com/login' });
    const res = createMockResponse({
      headers: { 'Set-Cookie': `token=${token}; HttpOnly` }
    });

    const finding = JWT_004.check(req, res);
    expect(finding).not.toBeNull();
  });

  it('should not flag JWT over HTTPS', () => {
    const req = createMockRequest({ 
        url: 'https://api.example.com/login',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_004.check(req, res);
    expect(finding).toBeNull();
  });
});
