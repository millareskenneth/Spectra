import { RES_006 } from '../rules/RES-006';
import { createMockRequest, createMockResponse } from './test-utils';

describe('RES-006: Server Technology Fingerprint', () => {
  const mockReq = createMockRequest();

  it('should flag X-Powered-By header', () => {
    const res = createMockResponse({
      headers: {
        'X-Powered-By': 'Express'
      }
    });

    const finding = RES_006.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('X-Powered-By: Express');
  });

  it('should flag Server header with version info', () => {
    const res = createMockResponse({
      headers: {
        'Server': 'Apache/2.4.41 (Ubuntu)'
      }
    });

    const finding = RES_006.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('Server: Apache/2.4.41');
  });

  it('should not flag generic Server header without version', () => {
    const res = createMockResponse({
      headers: {
        'Server': 'Cloudflare'
      }
    });

    const finding = RES_006.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should flag WordPress generator meta tag in body', () => {
    const res = createMockResponse({
      body: '<html><head><meta name="generator" content="WordPress 5.8.1" /></head><body>...</body></html>'
    });

    const finding = RES_006.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('Body pattern for WordPress');
  });

  it('should flag ASP.NET version header', () => {
    const res = createMockResponse({
      headers: {
        'X-AspNet-Version': '4.0.30319'
      }
    });

    const finding = RES_006.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('X-AspNet-Version');
  });

  it('should flag Next.js fingerprint in body', () => {
    const res = createMockResponse({
      body: '<script id="__NEXT_DATA__" type="application/json">{}</script>'
    });

    const finding = RES_006.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('Next.js');
  });

  it('should not flag safe responses', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'application/json',
        'Cache-Control': 'no-store'
      },
      body: JSON.stringify({ status: 'success' })
    });

    const finding = RES_006.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
