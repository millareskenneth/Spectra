import { RES_004 } from '../rules/RES-004';
import { createMockRequest, createMockResponse } from './test-utils';

describe('RES-004: Excessive PII in Response', () => {
  const mockReq = createMockRequest();

  it('should flag an SSN in the response', () => {
    const res = createMockResponse({
      body: JSON.stringify({
        user: {
          name: 'John Doe',
          ssn: '123-45-6789'
        }
      })
    });

    const finding = RES_004.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.ruleId).toBe('RES-004');
    expect(finding?.evidence).toContain('Social Security Number (SSN)');
  });

  it('should flag a Credit Card Number', () => {
    const res = createMockResponse({
      body: 'Your payment with card 4111 1111 1111 1111 was successful.'
    });

    const finding = RES_004.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Credit Card Number');
  });

  it('should flag an email address', () => {
    const res = createMockResponse({
      body: JSON.stringify({
        contact: 'support@example.com',
        user_email: 'john.doe+extra@company.co.uk'
      })
    });

    const finding = RES_004.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Email Address');
  });

  it('should flag multiple PII types', () => {
    const res = createMockResponse({
      body: 'Call us at 555-123-4567 or email john@doe.com'
    });

    const finding = RES_004.check(mockReq, res);
    expect(finding).not.toBeNull();
    expect(finding?.message).toContain('Phone Number');
    expect(finding?.message).toContain('Email Address');
  });

  it('should not flag safe response bodies', () => {
    const res = createMockResponse({
      body: JSON.stringify({
        id: 123,
        status: 'active',
        version: '1.0.2'
      })
    });

    const finding = RES_004.check(mockReq, res);
    expect(finding).toBeNull();
  });
});
