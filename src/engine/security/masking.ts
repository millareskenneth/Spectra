/**
 * Masks sensitive values before storing or displaying them.
 * Example: "sk_live_abc123xyz789" -> "sk_l************z789"
 */
export function maskValue(value: string): string {
  if (!value) return '';
  if (value.length <= 8) return '****';
  return value.slice(0, 4) + '*'.repeat(value.length - 8) + value.slice(-4);
}
