import { SecurityRule, SecurityFinding } from '../../types';

const SENSITIVE_ENDPOINTS = ['/login', '/signin', '/signup', '/auth', '/me', '/profile', '/user', '/settings', '/account'];
const DB_FIELD_INDICATORS = [
  'created_at', 'updated_at', 'deleted_at', 
  'createdAt', 'updatedAt', 'deletedAt',
  '__v', '_id', 'is_active', 'is_admin', 'is_deleted',
  'version_id', 'row_version', 'timestamp'
];

export const RES_007: SecurityRule = {
  id: 'RES-007',
  name: 'Full Database Row Leak',
  category: 'data-leak',
  severity: 'high',
  message: 'Authentication or profile endpoints appear to return full database rows without filtering.',
  recommendation: 'Use Data Transfer Objects (DTOs) or explicit field selection to ensure only necessary fields are returned in API responses. Never return internal database metadata like version numbers or timestamps unless required.',
  check: (req, res): SecurityFinding | null => {
    const url = req.url.toLowerCase();
    const isSensitiveEndpoint = SENSITIVE_ENDPOINTS.some(endpoint => url.includes(endpoint));

    if (!isSensitiveEndpoint || !res.body) {
      return null;
    }

    try {
      const body = JSON.parse(res.body);
      
      const analyzeObject = (obj: any): { metadataFields: string[], totalFields: number } | null => {
        if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return null;

        const keys = Object.keys(obj);
        const metadataFields = keys.filter(key => DB_FIELD_INDICATORS.includes(key));
        
        return {
          metadataFields,
          totalFields: keys.length
        };
      };

      // Check top-level or 'user'/'data' nested object
      const targets = [body];
      if (body.user) targets.push(body.user);
      if (body.data) targets.push(body.data);
      if (Array.isArray(body)) targets.push(...body.slice(0, 5)); // Check first few if it's an array

      for (const target of targets) {
        const stats = analyzeObject(target);
        if (stats) {
          const isHighMetadataCount = stats.metadataFields.length >= 4;
          const isExcessiveFields = stats.totalFields > 20;

          if (isHighMetadataCount || isExcessiveFields) {
            return {
              ruleId: 'RES-007',
              severity: 'high',
              category: 'data-leak',
              name: 'Full Database Row Leak',
              message: `Potential full DB row leak detected on ${isHighMetadataCount ? 'metadata' : 'field count'}.`,
              evidence: `Metadata fields: [${stats.metadataFields.join(', ')}], Total fields: ${stats.totalFields}`,
              recommendation: 'Filter database rows before sending them to the client. Avoid leaking internal columns like "created_at", "updated_at", or "__v".',
            };
          }
        }
      }
    } catch {
      // Not JSON, skip
    }

    return null;
  }
};
