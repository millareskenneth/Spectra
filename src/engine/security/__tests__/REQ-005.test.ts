import { REQ_005 } from '../rules/REQ-005';
import { createMockRequest, createMockResponse } from './test-utils';

describe('REQ-005: Private Key in Request Body', () => {
  const mockRes = createMockResponse();

  it('should flag an RSA private key in the body', () => {
    const req = createMockRequest({
      body: '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA75...'
    });

    const finding = REQ_005.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('BEGIN RSA PRIVATE KEY');
  });

  it('should flag a generic private key in the body', () => {
    const req = createMockRequest({
      body: '{"key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQ..."}'
    });

    const finding = REQ_005.check(req, mockRes);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('BEGIN PRIVATE KEY');
  });

  it('should not flag a public key', () => {
    const req = createMockRequest({
      body: '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...'
    });

    const finding = REQ_005.check(req, mockRes);
    expect(finding).toBeNull();
  });

  it('should not flag empty body', () => {
    const req = createMockRequest({
      body: null
    });

    const finding = REQ_005.check(req, mockRes);
    expect(finding).toBeNull();
  });
});
