import { RES_003 } from '../rules/RES-003';
import { createMockRequest, createMockResponse } from './test-utils';

describe('RES-003: Sensitive Fields in Auth Response', () => {
  it('should flag a password in the response of a login endpoint', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1/login' });
    const res = createMockResponse({
      body: JSON.stringify({
        status: 'success',
        user: {
          id: 123,
          email: 'user@example.com',
          password: 'plain-text-password-leak'
        }
      })
    });

    const finding = RES_003.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('RES-003');
    expect(finding?.evidence).toContain('password');
  });

  it('should flag a salt in a register response', () => {
    const req = createMockRequest({ url: 'https://api.example.com/register' });
    const res = createMockResponse({
      body: JSON.stringify({
        id: 456,
        salt: 'random-salt-value'
      })
    });

    const finding = RES_003.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('salt');
  });

  it('should flag sensitive fields in nested objects', () => {
    const req = createMockRequest({ url: 'https://api.example.com/auth/callback' });
    const res = createMockResponse({
      body: JSON.stringify({
        session: {
          user_info: {
            details: {
              hashed_password: '...'
            }
          }
        }
      })
    });

    const finding = RES_003.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('hashed_password');
  });

  it('should not flag sensitive fields in non-auth endpoints', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1/products/123' });
    const res = createMockResponse({
      body: JSON.stringify({
        name: 'Product Name',
        description: 'This is a secret_phrase for a game product'
      })
    });

    const finding = RES_003.check(req, res);
    expect(finding).toBeNull();
  });

  it('should not flag safe response bodies in auth endpoints', () => {
    const req = createMockRequest({ url: 'https://api.example.com/login' });
    const res = createMockResponse({
      body: JSON.stringify({
        token: 'ey...',
        expires_in: 3600
      })
    });

    const finding = RES_003.check(req, res);
    expect(finding).toBeNull();
  });
});
