import { RES_002 } from '../rules/RES-002';
import { createMockRequest, createMockResponse } from './test-utils';

describe('RES-002: Internal Server Path Exposure', () => {
  const mockReq = createMockRequest();

  it('should flag a Linux home path', () => {
    const res = createMockResponse({
      body: 'Error writing to /home/ubuntu/uploads/file.txt'
    });

    const finding = RES_002.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('/home/ubuntu');
  });

  it('should flag a Windows user path', () => {
    const res = createMockResponse({
      body: 'Permission denied: C:\\Users\\Administrator\\config.json'
    });

    const finding = RES_002.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('C:\\Users\\Administrator');
  });

  it('should flag a sensitive etc path', () => {
    const res = createMockResponse({
      body: 'Could not read /etc/passwd'
    });

    const finding = RES_002.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('/etc/passwd');
  });

  it('should flag a generic deep path pattern', () => {
    const res = createMockResponse({
      body: 'Module not found: /app/node_modules/express/lib/router/index.js'
    });

    const finding = RES_002.check(mockReq, res);
    expect(finding).not.toBeNull();
  });

  it('should not flag relative paths or simple names', () => {
    const res = createMockResponse({
      body: JSON.stringify({ file: 'index.js', status: 'uploaded' })
    });

    const finding = RES_002.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
