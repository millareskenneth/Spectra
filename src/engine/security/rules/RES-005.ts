import { SecurityRule, SecurityFinding } from '../../types';

const DB_INTERNAL_PATTERNS = [
  // SQL Errors - PostgreSQL
  { name: 'PostgreSQL Error', regex: /PostgreSQL.*ERROR|syntax error at or near/i },
  { name: 'PostgreSQL Table/Column', regex: /relation "[^"]+" does not exist|column "[^"]+" does not exist/i },
  
  // SQL Errors - MySQL/MariaDB
  { name: 'MySQL Error', regex: /MySQL.*Error|You have an error in your SQL syntax|Unknown column '[^']+' in 'field list'/i },
  { name: 'MySQL Table', regex: /Table '[^']+' doesn't exist/i },

  // SQL Errors - SQL Server
  { name: 'SQL Server Error', regex: /SQL Server.*Driver|Microsoft OLE DB Provider|Unclosed quotation mark after the character string|Violation of PRIMARY KEY constraint/i },

  // SQL Errors - Oracle
  { name: 'Oracle Error', regex: /ORA-[0-9]{5}/i },

  // SQL Errors - SQLite
  { name: 'SQLite Error', regex: /sqlite3\.Error|near "[^"]+": syntax error|no such table: [^ ]+/i },

  // MongoDB Errors
  { name: 'MongoDB Error', regex: /MongoError:|writeError:|MongoNetworkError:|BSONObj size: [0-9]+ (0x[0-9a-f]+) is invalid/i },

  // Connection Strings
  { name: 'Database Connection String', regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|sqlite):\/\/[^:]+:[^@]+@[^/]+\//i },
  { name: 'ODBC/JDBC Connection String', regex: /Driver=\{[^\}]+\};|Server=[^;]+;Database=[^;]+;User ID=[^;]+;Password=[^;]+;/i }
];

export const RES_005: SecurityRule = {
  id: 'RES-005',
  name: 'Database Internals Leaked',
  category: 'data-leak',
  severity: 'medium',
  message: 'Database error messages or connection strings should not be exposed in API responses.',
  recommendation: 'Ensure your application handles database exceptions gracefully and returns generic error messages. Connection strings should never be part of any response.',
  check: (req, res): SecurityFinding | null => {
    if (!res.body) {
      return null;
    }

    for (const pattern of DB_INTERNAL_PATTERNS) {
      if (pattern.regex.test(res.body)) {
        return {
          ruleId: 'RES-005',
          severity: 'medium',
          category: 'data-leak',
          name: 'Database Internals Leaked',
          message: `${pattern.name} detected in response body.`,
          evidence: `Found pattern: ${pattern.name}`,
          recommendation: 'Sanitize error messages to remove database internal details and ensure connection strings are not leaked.',
        };
      }
    }

    return null;
  }
};
