import { REQ_001 } from '../rules/REQ-001';
import { createMockRequest, createMockResponse } from './test-utils';

describe('REQ-001: API Key or Secret in URL', () => {
  const mockRes = createMockResponse();

  it('should flag an API key in the query string', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/data?api_key=sk_live_1234567890abcdef'
    });

    const finding = REQ_001.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('REQ-001');
    expect(finding?.evidence).toContain('api_key=sk_l');
    expect(finding?.evidence).toContain('bcdef');
    expect(finding?.evidence).not.toContain('1234567890'); // masked
  });

  it('should flag an access token in the query string', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/data?access_token=ya29.GlutB...'
    });

    const finding = REQ_001.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('access_token');
  });

  it('should not flag safe query parameters', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/data?id=123&query=search'
    });

    const finding = REQ_001.check(req, mockRes);
    expect(finding).toBeNull();
  });

  it('should handle malformed URLs gracefully', () => {
    const req = createMockRequest({
      url: 'not-a-url'
    });

    const finding = REQ_001.check(req, mockRes);
    expect(finding).toBeNull();
  });
});
