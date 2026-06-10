import { CapturedRequest, CapturedResponse, SecurityFinding, SecurityRule } from '../types';

export class RuleEngine {
  private rules: SecurityRule[] = [];

  constructor(rules: SecurityRule[] = []) {
    this.rules = rules;
  }

  public registerRule(rule: SecurityRule): void {
    this.rules.push(rule);
  }

  public scan(req: CapturedRequest, res: CapturedResponse): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const rule of this.rules) {
      try {
        const finding = rule.check(req, res);
        if (finding) {
          findings.push(finding);
        }
      } catch (error) {
        console.error(`Error executing rule ${rule.id}:`, error);
        // Rules should not throw, but we catch just in case to avoid crashing the engine
      }
    }

    return findings;
  }
}
