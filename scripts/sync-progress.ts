import * as fs from 'fs';
import * as path from 'path';

const PROGRESS_FILE = 'FUNCTIONS_PROGRESS.md';
const RULES_DIR = 'src/engine/security/rules';

function syncProgress() {
  if (!fs.existsSync(PROGRESS_FILE)) {
    console.error(`${PROGRESS_FILE} not found.`);
    return;
  }

  let content = fs.readFileSync(PROGRESS_FILE, 'utf8');
  const ruleFiles = fs.readdirSync(RULES_DIR).filter(f => f.endsWith('.ts'));
  const implementedRules = ruleFiles.map(f => f.replace('.ts', '').toUpperCase());

  // Pattern to match: - [ ] REQ-001: ...
  const lines = content.split('\n');
  const updatedLines = lines.map(line => {
    const match = line.match(/- \[( |x)\] ([A-Z]+-\d{3}):/);
    if (match) {
      const ruleId = match[2];
      const isImplemented = implementedRules.includes(ruleId);
      if (isImplemented) {
        return line.replace('- [ ]', '- [x]');
      } else {
        return line.replace('- [x]', '- [ ]');
      }
    }
    return line;
  });

  const updatedContent = updatedLines.join('\n');
  if (content !== updatedContent) {
    fs.writeFileSync(PROGRESS_FILE, updatedContent);
    console.log(`Updated ${PROGRESS_FILE}`);
  } else {
    console.log(`${PROGRESS_FILE} is already up to date.`);
  }
}

syncProgress();
