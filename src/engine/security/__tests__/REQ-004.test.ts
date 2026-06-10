import { REQ_004 } from '../rules/REQ-004';
import { createMockRequest, createMockResponse } from './test-utils';

describe('REQ-004: Authorization Token over HTTP', () => {
  const mockRes = createMockResponse();

  it('should flag Authorization header over HTTP', () => {
    const req = createMockRequest({
      url: 'http://api.example.com/v1/user',
      headers: {
        'Authorization': 'Bearer some-token'
      }
    });

    const finding = REQ_004.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('REQ-004');
    expect(finding?.message).toContain('Authorization');
  });

  it('should flag x-api-key over HTTP', () => {
    const req = createMockRequest({
      url: 'http://api.example.com/v1/user',
      headers: {
        'x-api-key': 'secret-key'
      }
    });

    const finding = REQ_004.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('x-api-key');
  });

  it('should not flag sensitive headers over HTTPS', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/v1/user',
      headers: {
        'Authorization': 'Bearer some-token'
      }
    });

    const finding = REQ_004.check(req, mockRes);
    expect(finding).toBeNull();
  });

  it('should not flag non-sensitive headers over HTTP', () => {
    const req = createMockRequest({
      url: 'http://api.example.com/v1/user',
      headers: {
        'Accept': 'application/json'
      }
    });

    const finding = REQ_004.check(req, mockRes);
    expect(finding).toBeNull();
  });
});
