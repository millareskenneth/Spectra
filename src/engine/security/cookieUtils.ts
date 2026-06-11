/**
 * Simplistic Set-Cookie parser.
 * Handles potential multiple cookies joined by newlines.
 */
export function getCookies(headers: Record<string, string>): string[] {
  const setCookie = headers['Set-Cookie'] || headers['set-cookie'] || '';
  if (!setCookie) return [];
  
  // Some capture engines might join multiple Set-Cookie headers with newlines
  return setCookie.split(/\r?\n/).filter(c => c.trim().length > 0);
}

export function hasCookieFlag(cookie: string, flag: string): boolean {
  const parts = cookie.split(';').map(p => p.trim().toLowerCase());
  return parts.includes(flag.toLowerCase());
}

export function getCookieValue(cookie: string, key: string): string | null {
  const parts = cookie.split(';').map(p => p.trim());
  for (const part of parts) {
    if (part.toLowerCase().startsWith(key.toLowerCase() + '=')) {
      return part.substring(key.length + 1);
    }
  }
  return null;
}
