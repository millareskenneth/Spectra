import { REQ_002 } from '../rules/REQ-002';
import { createMockRequest, createMockResponse } from './test-utils';

describe('REQ-002: Password in URL', () => {
  const mockRes = createMockResponse();

  it('should flag a password in the query string', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/login?password=mysecretpassword123'
    });

    const finding = REQ_002.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('REQ-002');
    expect(finding?.evidence).toContain('password=myse');
    expect(finding?.evidence).toContain('d123');
    expect(finding?.evidence).not.toContain('retpasswor'); // masked
  });

  it('should flag "pwd" in the query string', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/login?pwd=anothersecret'
    });

    const finding = REQ_002.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('pwd');
  });

  it('should flag "passphrase" in the query string', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/login?passphrase=correct-horse-battery-staple'
    });

    const finding = REQ_002.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('passphrase');
  });

  it('should not flag safe query parameters', () => {
    const req = createMockRequest({
      url: 'https://api.example.com/data?id=123&username=jdoe'
    });

    const finding = REQ_002.check(req, mockRes);
    expect(finding).toBeNull();
  });
});
