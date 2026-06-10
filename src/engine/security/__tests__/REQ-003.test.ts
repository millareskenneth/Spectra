import { REQ_003 } from '../rules/REQ-003';
import { createMockRequest, createMockResponse } from './test-utils';

describe('REQ-003: AWS Credentials Detected', () => {
  const mockRes = createMockResponse();

  it('should flag an AWS Access Key ID in the URL', () => {
    const req = createMockRequest({
      url: 'https://example.com/?key=AKIAIOSFODNN7EXAMPLE'
    });

    const finding = REQ_003.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Access Key ID');
    expect(finding?.evidence).toBe('AKIA************MPLE');
  });

  it('should flag an AWS Secret Access Key in the body', () => {
    const req = createMockRequest({
      body: JSON.stringify({
        secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
      })
    });

    const finding = REQ_003.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Secret Access Key');
  });

  it('should not flag a 40-character hex string (likely not AWS secret)', () => {
    const req = createMockRequest({
      body: JSON.stringify({
        hash: 'a9993e364706816aba3e25717850c26c9cd0d89d'
      })
    });

    const finding = REQ_003.check(req, mockRes);
    expect(finding).toBeNull();
  });

  it('should flag an AWS Access Key ID in headers', () => {
    const req = createMockRequest({
      headers: {
        'X-AWS-Key': 'AKIAI44QH8DHBEXAMPLE'
      }
    });

    const finding = REQ_003.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Access Key ID');
  });
});
