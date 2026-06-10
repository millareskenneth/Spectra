import { RES_001 } from '../rules/RES-001';
import { createMockRequest, createMockResponse } from './test-utils';

describe('RES-001: Stack Trace Exposure', () => {
  const mockReq = createMockRequest();

  it('should flag a Node.js stack trace in the response', () => {
    const res = createMockResponse({
      body: 'Error: Something went wrong\n    at Object.<anonymous> (/app/index.js:10:15)\n    at Module._compile (internal/modules/cjs/loader.js:1137:30)'
    });

    const finding = RES_001.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('RES-001');
    expect(finding?.severity).toBe('high');
  });

  it('should flag a Python stack trace', () => {
    const res = createMockResponse({
      body: 'Traceback (most recent call last):\n  File "example.py", line 5, in <module>\n    greet("Alice")'
    });

    const finding = RES_001.check(mockReq, res);
    expect(finding).not.toBeNull();
  });

  it('should flag "Caused by:" label', () => {
    const res = createMockResponse({
      body: 'Internal Server Error. Caused by: java.sql.SQLException: Connection refused'
    });

    const finding = RES_001.check(mockReq, res);
    expect(finding).not.toBeNull();
  });

  it('should not flag generic error messages', () => {
    const res = createMockResponse({
      body: JSON.stringify({ error: 'Internal Server Error', code: 500 })
    });

    const finding = RES_001.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
