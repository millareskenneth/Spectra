import { RES_007 } from '../rules/RES-007';
import { createMockRequest, createMockResponse } from './test-utils';

describe('RES-007: Full Database Row Leak', () => {
  it('should flag a response with many DB metadata fields on /me endpoint', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1/me' });
    const res = createMockResponse({
      body: JSON.stringify({
        id: 123,
        username: 'johndoe',
        email: 'john@example.com',
        created_at: '2023-01-01T00:00:00Z',
        updated_at: '2023-06-01T00:00:00Z',
        __v: 0,
        _id: '507f1f77bcf86cd799439011',
        is_active: true
      })
    });

    const finding = RES_007.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('created_at');
    expect(finding?.evidence).toContain('__v');
  });

  it('should flag excessive field count on /profile endpoint', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1/profile' });
    const fields: Record<string, any> = { id: 1, name: 'John' };
    for (let i = 0; i < 25; i++) {
      fields[`extra_field_${i}`] = 'value';
    }
    const res = createMockResponse({ body: JSON.stringify(fields) });

    const finding = RES_007.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('field count');
  });

  it('should flag leaks inside a "user" nested object', () => {
    const req = createMockRequest({ url: 'https://api.example.com/auth/login' });
    const res = createMockResponse({
      body: JSON.stringify({
        token: 'abc.123.xyz',
        user: {
          id: 456,
          createdAt: '2023-01-01',
          updatedAt: '2023-01-01',
          deletedAt: null,
          is_admin: false
        }
      })
    });

    const finding = RES_007.check(req, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('createdAt');
  });

  it('should not flag safe responses on non-sensitive endpoints', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1/products/123' });
    const res = createMockResponse({
      body: JSON.stringify({
        id: 123,
        name: 'Widget',
        created_at: '2023-01-01',
        updated_at: '2023-01-01',
        __v: 0,
        _id: 'abc',
        is_active: true
      })
    });

    const finding = RES_007.check(req, res);
    expect(finding).toBeNull();
  });

  it('should not flag filtered user objects', () => {
    const req = createMockRequest({ url: 'https://api.example.com/v1/me' });
    const res = createMockResponse({
      body: JSON.stringify({
        id: 123,
        username: 'johndoe',
        email: 'john@example.com'
      })
    });

    const finding = RES_007.check(req, res);
    expect(finding).toBeNull();
  });
});
