export interface CapturedRequest {
  id: string;
  timestamp: number;
  method: string;
  url: string;
  headers: Record<string, string>;
  body: string | null;
  packageName?: string; // Android only
  bundleId?: string;    // iOS only
}

export interface CapturedResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string | null;
  durationMs: number;
  bodySize: number;
}

export interface SecurityFinding {
  ruleId: string; // e.g. "REQ-001"
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: 'exposure' | 'transport' | 'headers' | 'data-leak' | 'auth' | 'jwt' | 'cookie';
  name: string;
  message: string;
  evidence: string; // ALWAYS masked
  recommendation: string;
}

export interface SecurityRule {
  id: string;
  name: string;
  category: SecurityFinding['category'];
  severity: SecurityFinding['severity'];
  message: string;
  recommendation: string;
  check: (req: CapturedRequest, res: CapturedResponse) => SecurityFinding | null;
}
