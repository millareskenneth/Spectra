import { JWT_002 } from '../rules/JWT-002';
import { createMockRequest, createMockResponse } from './test-utils';

describe('JWT_002: missing exp claim', () => {
  const createJWT = (payload: object) => {
    const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64').replace(/=/g, '');
    const p = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/=/g, '');
    return `${h}.${p}.signature`;
  };

  it('should flag JWT missing exp claim', () => {
    const token = createJWT({ sub: '123', name: 'John Doe' });
    const req = createMockRequest({
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_002.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('JWT-002');
  });

  it('should not flag JWT with exp claim', () => {
    const token = createJWT({ sub: '123', exp: Math.floor(Date.now() / 1000) + 3600 });
    const req = createMockRequest({
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_002.check(req, res);
    expect(finding).toBeNull();
  });

  it('should flag JWT in cookies missing exp', () => {
    const token = createJWT({ sub: '456' });
    const req = createMockRequest({
      headers: { 'Cookie': `auth=${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_002.check(req, res);
    expect(finding).not.toBeNull();
  });
});
