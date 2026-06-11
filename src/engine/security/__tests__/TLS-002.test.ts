import { TLS_002 } from '../rules/TLS-002';
import { createMockRequest, createMockResponse } from './test-utils';

describe('TLS-002: certificate pinning detected', () => {
  const mockReq = createMockRequest();

  it('should flag potential pinning when statusCode is 0', () => {
    const res = createMockResponse({
      statusCode: 0,
      body: null
    });

    const finding = TLS_002.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('TLS-002');
    expect(finding?.severity).toBe('info');
  });

  it('should not flag successful connections', () => {
    const res = createMockResponse({
      statusCode: 200
    });

    const finding = TLS_002.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should not flag standard server errors', () => {
    const res = createMockResponse({
      statusCode: 500
    });

    const finding = TLS_002.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
