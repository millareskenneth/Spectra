import { JWT_003 } from '../rules/JWT-003';
import { createMockRequest, createMockResponse } from './test-utils';

describe('JWT-003: sensitive PII in payload', () => {
  const createJWT = (payload: object) => {
    const h = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64').replace(/=/g, '');
    const p = Buffer.from(JSON.stringify(payload)).toString('base64').replace(/=/g, '');
    return `${h}.${p}.signature`;
  };

  it('should flag JWT with SSN in payload', () => {
    const token = createJWT({ sub: '123', ssn: '123-45-6789' });
    const req = createMockRequest({
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_003.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('ssn');
  });

  it('should flag JWT with birthdate in nested object', () => {
    const token = createJWT({ 
        sub: '123', 
        user: {
            details: {
                dob: '1990-01-01'
            }
        } 
    });
    const req = createMockRequest({
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_003.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('dob');
  });

  it('should not flag JWT with only non-sensitive claims', () => {
    const token = createJWT({ sub: '123', iat: 1600000000, exp: 1700000000, scopes: ['read'] });
    const req = createMockRequest({
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const res = createMockResponse();

    const finding = JWT_003.check(req, res);
    expect(finding).toBeNull();
  });
});
