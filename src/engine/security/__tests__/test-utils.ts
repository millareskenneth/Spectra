import { CapturedRequest, CapturedResponse } from '../../types';

export const createMockRequest = (overrides: Partial<CapturedRequest> = {}): CapturedRequest => ({
  id: 'req-123',
  timestamp: Date.now(),
  method: 'GET',
  url: 'https://api.example.com/v1/user',
  headers: {
    'Accept': 'application/json',
    'User-Agent': 'Spectra/1.0'
  },
  body: null,
  ...overrides,
});

export const createMockResponse = (overrides: Partial<CapturedResponse> = {}): CapturedResponse => ({
  statusCode: 200,
  headers: {
    'Content-Type': 'application/json',
    'Server': 'nginx'
  },
  body: JSON.stringify({ status: 'ok' }),
  durationMs: 150,
  bodySize: 24,
  ...overrides,
});
