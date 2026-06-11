import { JWT_001 } from '../rules/JWT-001';
import { createMockRequest, createMockResponse } from './test-utils';

describe('JWT-001: alg: none', () => {
  const createJWT = (header: object) => {
    const h = Buffer.from(JSON.stringify(header)).toString('base64').replace(/=/g, '');
    const p = Buffer.from(JSON.stringify({ sub: '123' })).toString('base64').replace(/=/g, '');
    return `${h}.${p}.signature`;
  };

  it('should flag JWT with alg: none', () => {
    const token = createJWT({ alg: 'none', typ: 'JWT' });
    const req = createMockRequest({
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    const res = createMockResponse();

    const finding = JWT_001.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('JWT-001');
    expect(finding?.severity).toBe('critical');
  });

  it('should flag JWT with ALG: NONE (case insensitive)', () => {
    const token = createJWT({ alg: 'NONE' });
    const req = createMockRequest({
      headers: {
        'Cookie': `session=${token}`
      }
    });
    const res = createMockResponse();

    const finding = JWT_001.check(req, res);
    expect(finding).not.toBeNull();
  });

  it('should not flag JWT with HS256', () => {
    const token = createJWT({ alg: 'HS256' });
    const req = createMockRequest({
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    const res = createMockResponse();

    const finding = JWT_001.check(req, res);
    expect(finding).toBeNull();
  });

  it('should not flag non-JWT headers', () => {
    const req = createMockRequest({
      headers: {
        'Authorization': 'Basic YWRtaW46cGFzc3dvcmQ='
      }
    });
    const res = createMockResponse();

    const finding = JWT_001.check(req, res);
    expect(finding).toBeNull();
  });
});
