const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = process.cwd();
const PROGRESS_FILE = path.join(PROJECT_ROOT, 'FUNCTIONS_PROGRESS.md');
const README_FILE = path.join(PROJECT_ROOT, 'README.md');
const RULES_DIR = path.join(PROJECT_ROOT, 'src/engine/security/rules');

function syncProgress() {
  if (!fs.existsSync(PROGRESS_FILE)) {
    console.error(`${PROGRESS_FILE} not found.`);
    return;
  }

  let progressContent = fs.readFileSync(PROGRESS_FILE, 'utf8');
  const ruleFiles = fs.readdirSync(RULES_DIR).filter(f => f.endsWith('.ts'));
  const implementedRules = ruleFiles.map(f => f.replace('.ts', '').toUpperCase());

  // 1. Update FUNCTIONS_PROGRESS.md
  const progressLines = progressContent.split('\n');
  const updatedProgressLines = progressLines.map(line => {
    const match = line.match(/- \[( |x)\] ([A-Z]+-\d{3}):/);
    if (match) {
      const ruleId = match[2];
      const isImplemented = implementedRules.includes(ruleId);
      return isImplemented ? line.replace('- [ ]', '- [x]') : line.replace('- [x]', '- [ ]');
    }
    return line;
  });

  const finalProgressContent = updatedProgressLines.join('\n');
  if (progressContent !== finalProgressContent) {
    fs.writeFileSync(PROGRESS_FILE, finalProgressContent);
    console.log(`Updated ${PROGRESS_FILE}`);
  }

  // 2. Update README.md Progress Section
  if (fs.existsSync(README_FILE)) {
    let readmeContent = fs.readFileSync(README_FILE, 'utf8');
    
    // Extract checklist from progress file
    const checklistStart = finalProgressContent.indexOf('## Request Rules');
    if (checklistStart === -1) return;
    
    const checklist = finalProgressContent.substring(checklistStart);

    const startMarker = '<!-- START-RULES-PROGRESS -->';
    const endMarker = '<!-- END-RULES-PROGRESS -->';
    
    const startIndex = readmeContent.indexOf(startMarker);
    const endIndex = readmeContent.indexOf(endMarker);

    if (startIndex !== -1 && endIndex !== -1) {
      const before = readmeContent.substring(0, startIndex + startMarker.length);
      const after = readmeContent.substring(endIndex);
      const newReadmeContent = `${before}\n\n${checklist}\n\n${after}`;
      
      // Update the badge too
      const totalRules = (finalProgressContent.match(/- \[( |x)\]/g) || []).length;
      const doneRules = implementedRules.length;
      const badgePattern = /Security_Rules-\d+\/\d+-critical/;
      const newBadge = `Security_Rules-${doneRules}/${totalRules}-critical`;
      
      const finalReadme = newReadmeContent.replace(badgePattern, newBadge);

      if (readmeContent !== finalReadme) {
        fs.writeFileSync(README_FILE, finalReadme);
        console.log(`Updated ${README_FILE} progress section and badge.`);
      }
    }
  }
}

syncProgress();
