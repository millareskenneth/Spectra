import { HDR_003 } from '../rules/HDR-003';
import { createMockRequest, createMockResponse } from './test-utils';

describe('HDR-003: Missing X-Content-Type-Options', () => {
  const mockReq = createMockRequest();

  it('should flag missing X-Content-Type-Options', () => {
    const res = createMockResponse({
      headers: {
        'Content-Type': 'application/json'
      }
    });

    const finding = HDR_003.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('HDR-003');
  });

  it('should flag incorrect X-Content-Type-Options value', () => {
    const res = createMockResponse({
      headers: {
        'X-Content-Type-Options': 'sniff'
      }
    });

    const finding = HDR_003.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.evidence).toContain('sniff');
  });

  it('should not flag when set to nosniff', () => {
    const res = createMockResponse({
      headers: {
        'X-Content-Type-Options': 'nosniff'
      }
    });

    const finding = HDR_003.check(mockReq, res);
    expect(finding).toBeNull();
  });

  it('should handle case-insensitivity', () => {
    const res = createMockResponse({
      headers: {
        'x-content-type-options': 'NOSNIFF'
      }
    });

    const finding = HDR_003.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
