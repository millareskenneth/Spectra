import { CapturedRequest, CapturedResponse } from '../types';

/**
 * Extracts potential JWTs from headers.
 * Looks for the common pattern 'ey...' (base64 for '{' or '[' which starts most JWT headers/payloads)
 */
export function extractJWTs(headers: Record<string, string>): string[] {
  const tokens: string[] = [];
  // JWT regex: header.payload.signature (all base64url)
  const jwtPattern = /ey[a-zA-Z0-9_-]+\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*/g;

  for (const value of Object.values(headers)) {
    const matches = value.match(jwtPattern);
    if (matches) {
      tokens.push(...matches);
    }
  }

  return tokens;
}

function base64UrlDecode(str: string): string {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  return Buffer.from(base64, 'base64').toString();
}

export function decodeJWTHeader(token: string): any | null {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    return JSON.parse(base64UrlDecode(parts[0]));
  } catch {
    return null;
  }
}

export function decodeJWTPayload(token: string): any | null {
  try {
    const parts = token.split('.');
    if (parts.length < 2) return null;
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return null;
  }
}
