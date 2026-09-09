/**
 * Threat Detection Security Module — File Scanner
 * Analyzes a filename and detects signs of malicious or dangerous files
 * based on extension patterns, double extensions, and naming conventions.
 * 
 * Output Contract:
 * {
 *   score: number (0-100),
 *   reasons: string[],
 *   metadata: {
 *     originalFilename: string,
 *     detectedExtension: string,
 *     isDoubleExtension: boolean,
 *     fakeExtension: string,
 *     realExtension: string,
 *     extensionRiskLevel: "Low" | "Medium" | "High" | "Very High"
 *   }
 * }
 */

// Extension Risk Categories
const VERY_HIGH_RISK_EXTENSIONS = new Set([
  '.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
  '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
  '.ps1', '.psm1',
  '.msi', '.msp'
]);

const HIGH_RISK_EXTENSIONS = new Set([
  '.jar', '.py', '.rb', '.sh',
  '.dll', '.sys',
  '.reg'
]);

const MODERATE_RISK_EXTENSIONS = new Set([
  '.zip', '.rar', '.7z', '.tar', '.gz',
  '.iso', '.img'
]);

// Known innocent disguise extensions (used in double extension attacks)
const INNOCENT_EXTENSIONS = new Map([
  ['.pdf', 'PDF'],
  ['.doc', 'Word document'],
  ['.docx', 'Word document'],
  ['.xls', 'Excel spreadsheet'],
  ['.xlsx', 'Excel spreadsheet'],
  ['.ppt', 'PowerPoint presentation'],
  ['.pptx', 'PowerPoint presentation'],
  ['.txt', 'text file'],
  ['.rtf', 'Rich Text document'],
  ['.csv', 'CSV file'],
  ['.jpg', 'image'],
  ['.jpeg', 'image'],
  ['.png', 'image'],
  ['.gif', 'image'],
  ['.mp3', 'audio file'],
  ['.mp4', 'video file'],
  ['.avi', 'video file']
]);

// Common Windows & system filenames mimicked by malware
const SYSTEM_FILENAMES = new Set([
  'svchost.exe', 'explorer.exe', 'winlogon.bat', 'winlogon.exe',
  'services.exe', 'lsass.exe', 'csrss.exe', 'smss.exe',
  'cmd.exe', 'taskmgr.exe', 'rundll32.exe', 'spoolsv.exe',
  'dwm.exe', 'system.exe', 'conhost.exe'
]);

// Social Engineering Keywords in Filenames
const SOCIAL_ENGINEERING_KEYWORDS = [
  // Urgency or financial
  'urgent', 'invoice', 'payment', 'salary', 'offer',
  'final', 'important', 'confidential', 'bank', 'statement', 'receipt', 'overdue',
  // Software / cracked tools
  'setup', 'install', 'update', 'crack', 'keygen', 'patch', 'hack', 'activator',
  // Media keywords
  'video', 'photo', 'image', 'picture', 'pic'
];

/**
 * Strips path delimiters and returns the base filename.
 */
function getBasename(filePath) {
  if (!filePath) return '';
  return filePath.split(/[/\\]/).pop();
}

/**
 * Scans a filename and calculates a threat risk score with reasons and metadata.
 * 
 * @param {string} filename - The filename to analyze
 * @returns {{ score: number, reasons: string[], metadata: object }}
 */
export function scanFile(filename) {
  // Edge case: empty or invalid input
  if (!filename || typeof filename !== 'string' || filename.trim().length === 0) {
    return {
      score: 0,
      reasons: ['No filename provided for analysis'],
      metadata: {
        originalFilename: filename || '',
        detectedExtension: '',
        isDoubleExtension: false,
        fakeExtension: '',
        realExtension: '',
        extensionRiskLevel: 'Low'
      }
    };
  }

  const originalFilename = filename;
  const baseName = getBasename(filename);
  let score = 0;
  const reasons = [];

  // Parse extensions
  // Note: Handle filenames with spaces between extensions (e.g. "invoice.pdf   .exe")
  const trimmedBase = baseName.trim();
  const rawParts = trimmedBase.split('.');

  let realExtension = '';
  let fakeExtension = '';
  let isDoubleExtension = false;
  let extensionRiskLevel = 'Low';

  if (rawParts.length > 1) {
    realExtension = '.' + rawParts[rawParts.length - 1].trim().toLowerCase();
  }

  // 1. Extension Risk Assessment
  if (VERY_HIGH_RISK_EXTENSIONS.has(realExtension)) {
    extensionRiskLevel = 'Very High';
  } else if (HIGH_RISK_EXTENSIONS.has(realExtension)) {
    extensionRiskLevel = 'High';
  } else if (MODERATE_RISK_EXTENSIONS.has(realExtension)) {
    extensionRiskLevel = 'Medium';
  } else {
    extensionRiskLevel = 'Low';
  }

  // 2. Double Extension Detection
  // e.g. invoice.pdf.exe, image.jpg.bat, document.docx.vbs
  if (rawParts.length >= 3) {
    const candidateFakeExt = '.' + rawParts[rawParts.length - 2].trim().toLowerCase();
    const isRealExtRisky = extensionRiskLevel === 'Very High' || extensionRiskLevel === 'High' || extensionRiskLevel === 'Medium';
    const isFakeExtInnocent = INNOCENT_EXTENSIONS.has(candidateFakeExt);

    if (isRealExtRisky && isFakeExtInnocent) {
      isDoubleExtension = true;
      fakeExtension = candidateFakeExt;
      score += 35;
      reasons.push(`Double extension detected — real extension is ${realExtension}`);

      const disguiseDescription = INNOCENT_EXTENSIONS.get(fakeExtension) || fakeExtension.slice(1).toUpperCase();
      reasons.push(`Executable file disguised as ${disguiseDescription}`);
    }
  }

  // Add extension risk points and reason
  if (extensionRiskLevel === 'Very High') {
    score += 40;
    reasons.push(`Very high risk extension: ${realExtension}`);
  } else if (extensionRiskLevel === 'High') {
    score += 25;
    reasons.push(`High risk extension: ${realExtension}`);
  } else if (extensionRiskLevel === 'Medium') {
    score += 10;
    reasons.push(`Moderate risk extension: ${realExtension}`);
  }

  // 3. Misleading Filename Detection
  const lowerBase = baseName.toLowerCase();

  // A. System file mimicry
  if (SYSTEM_FILENAMES.has(lowerBase)) {
    score += 20;
    reasons.push(`Misleading system filename: pretending to be a system file (${baseName})`);
  }

  // B. Excessive spaces to hide extension (e.g. "invoice.pdf          .exe")
  if (/\s{3,}\.[a-zA-Z0-9]+$/i.test(baseName) || (baseName.includes('   ') && realExtension)) {
    score += 20;
    reasons.push('Filename contains excessive spaces to hide extension');
  }

  // C. Unicode lookalike / RTLO / Hidden characters check
  // U+202E (Right-to-Left Override), U+202D, U+200E, U+200F, U+200B-200D (zero-width)
  const hasSuspiciousUnicode = /[\u202A-\u202E\u200B-\u200D\uFEFF]/.test(baseName) ||
    // Cyrillic letters mixed in
    (/[\u0400-\u04FF]/.test(baseName) && /[a-zA-Z]/.test(baseName));

  if (hasSuspiciousUnicode) {
    score += 20;
    reasons.push('Filename contains suspicious Unicode lookalike or hidden characters');
  }

  // 4. Social Engineering Name Detection
  // Check the base name without extensions for social engineering words
  const nameWithoutExt = rawParts[0].toLowerCase();
  let detectedSocialKeyword = null;

  for (const kw of SOCIAL_ENGINEERING_KEYWORDS) {
    // Check if the keyword appears as a whole word or significant substring
    const regex = new RegExp(`\\b${kw}\\b|(?<=[^a-z])${kw}|${kw}(?=[^a-z])|^${kw}$`, 'i');
    if (regex.test(nameWithoutExt) || nameWithoutExt.includes(kw)) {
      detectedSocialKeyword = kw;
      score += 15;
      reasons.push(`Social engineering filename: ${kw}`);
      break; // One social engineering keyword detection suffices
    }
  }

  // 5. Extension and Name Mismatch
  // Only trigger if not already handled by double extension to avoid redundancy
  if (!isDoubleExtension) {
    const isMediaName = /^(photo|image|picture|pic|video|movie|clip)/i.test(nameWithoutExt);
    const isDocName = /^(invoice|document|report|receipt|statement|contract)/i.test(nameWithoutExt);

    if (isMediaName && (VERY_HIGH_RISK_EXTENSIONS.has(realExtension) || HIGH_RISK_EXTENSIONS.has(realExtension))) {
      score += 20;
      reasons.push(`Extension and name mismatch: name suggests media but extension is executable (${realExtension})`);
    } else if (isDocName && (realExtension === '.scr' || realExtension === '.bat' || realExtension === '.cmd' || realExtension === '.vbs' || realExtension === '.pif')) {
      score += 20;
      reasons.push(`Extension and name mismatch: name suggests document but extension is script/executable (${realExtension})`);
    }
  }

  // Cap the final score between 0 and 100
  const finalScore = Math.min(100, Math.max(0, score));

  return {
    score: finalScore,
    reasons,
    metadata: {
      originalFilename,
      detectedExtension: realExtension,
      isDoubleExtension,
      fakeExtension,
      realExtension,
      extensionRiskLevel
    }
  };
}

// CLI execution support: node fileScanner.js "your-filename.exe"
if (process.argv[1] && process.argv[1].endsWith('fileScanner.js') && process.argv[2]) {
  const result = scanFile(process.argv[2]);
  console.log(JSON.stringify(result, null, 2));
}
