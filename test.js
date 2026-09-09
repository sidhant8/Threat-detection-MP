/**
 * Threat Detection Security Module — Local Test Suite
 * Validates urlScanner.js and fileScanner.js against the strict output contract,
 * reference examples, detection features, scoring logic, and edge cases.
 */

import { scanURL } from './urlScanner.js';
import { scanFile } from './fileScanner.js';

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log(`  ✓ ${message}`);
  } else {
    failed++;
    console.error(`  ✗ FAIL: ${message}`);
  }
}

function assertContract(res, type) {
  assert(typeof res.score === 'number' && res.score >= 0 && res.score <= 100, `${type}: score must be a number between 0 and 100 (got ${res.score})`);
  assert(Array.isArray(res.reasons), `${type}: reasons must be an array`);
  assert(res.reasons.every(r => typeof r === 'string'), `${type}: every reason must be a string`);
  assert(typeof res.metadata === 'object' && res.metadata !== null && !Array.isArray(res.metadata), `${type}: metadata must be an object`);

  if (type === 'urlScanner') {
    assert(typeof res.metadata.protocol === 'string', 'urlScanner metadata.protocol must be a string');
    assert(typeof res.metadata.domain === 'string', 'urlScanner metadata.domain must be a string');
    assert(Array.isArray(res.metadata.suspiciousKeywordsFound), 'urlScanner metadata.suspiciousKeywordsFound must be an array');
    assert(['Low', 'Medium', 'High'].includes(res.metadata.tldRiskLevel), `urlScanner metadata.tldRiskLevel must be Low/Medium/High (got ${res.metadata.tldRiskLevel})`);
    assert(typeof res.metadata.isIPAddress === 'boolean', 'urlScanner metadata.isIPAddress must be a boolean');
    assert(typeof res.metadata.urlLength === 'number', 'urlScanner metadata.urlLength must be a number');
  } else if (type === 'fileScanner') {
    assert(typeof res.metadata.originalFilename === 'string', 'fileScanner metadata.originalFilename must be a string');
    assert(typeof res.metadata.detectedExtension === 'string', 'fileScanner metadata.detectedExtension must be a string');
    assert(typeof res.metadata.isDoubleExtension === 'boolean', 'fileScanner metadata.isDoubleExtension must be a boolean');
    assert(typeof res.metadata.fakeExtension === 'string', 'fileScanner metadata.fakeExtension must be a string');
    assert(typeof res.metadata.realExtension === 'string', 'fileScanner metadata.realExtension must be a string');
    assert(['Low', 'Medium', 'High', 'Very High'].includes(res.metadata.extensionRiskLevel), `fileScanner metadata.extensionRiskLevel must be Low/Medium/High/Very High (got ${res.metadata.extensionRiskLevel})`);
  }
}

console.log('====================================================');
console.log('1. TESTING urlScanner.js');
console.log('====================================================\n');

// Test 1: Reference Example from Specification
{
  console.log('Test 1.1: Reference Phishing URL (http://paypa1-secure-login.tk/verify?redirect=account)');
  const input = 'http://paypa1-secure-login.tk/verify?redirect=account';
  const res = scanURL(input);
  assertContract(res, 'urlScanner');
  assert(res.score === 95, `Expected score 95, got ${res.score}`);
  assert(res.metadata.protocol === 'http', 'Protocol is http');
  assert(res.metadata.domain === 'paypa1-secure-login.tk', 'Domain extracted properly');
  assert(res.metadata.tldRiskLevel === 'High', 'TLD risk level is High');
  assert(res.metadata.isIPAddress === false, 'isIPAddress is false');
  assert(res.metadata.urlLength === 53, `urlLength is 53 (got ${res.metadata.urlLength})`);
  assert(res.metadata.suspiciousKeywordsFound.includes('secure'), 'Keywords includes secure');
  assert(res.metadata.suspiciousKeywordsFound.includes('login'), 'Keywords includes login');
  assert(res.metadata.suspiciousKeywordsFound.includes('verify'), 'Keywords includes verify');
  assert(res.reasons.some(r => r.includes('HTTP — not secure')), 'Reason for HTTP present');
  assert(res.reasons.some(r => r.includes('spoof PayPal')), 'Reason for PayPal spoofing present');
  assert(res.reasons.some(r => r.includes('High risk TLD detected: .tk')), 'Reason for high risk TLD present');
  assert(res.reasons.some(r => r.includes('Suspicious keywords found')), 'Reason for suspicious keywords present');
  assert(res.reasons.some(r => r.includes('Redirect parameter detected')), 'Reason for redirect parameter present');
}

// Test 2: Clean Legitimate URL
{
  console.log('\nTest 1.2: Clean Legitimate URL (https://google.com)');
  const res = scanURL('https://google.com');
  assertContract(res, 'urlScanner');
  assert(res.score === 0, `Clean URL score should be 0, got ${res.score}`);
  assert(res.reasons.length === 0, 'Clean URL reasons should be empty');
  assert(res.metadata.tldRiskLevel === 'Low', 'TLD risk level should be Low');
  assert(res.metadata.isIPAddress === false, 'isIPAddress should be false');
}

// Test 3: IP Address as Domain
{
  console.log('\nTest 1.3: IP Address URL (http://192.168.1.1/login)');
  const res = scanURL('http://192.168.1.1/login');
  assertContract(res, 'urlScanner');
  assert(res.metadata.isIPAddress === true, 'isIPAddress is true');
  assert(res.reasons.some(r => r.includes('IP address used instead of domain name')), 'IP address reason present');
  assert(res.score >= 45, `Expected score >= 45 for HTTP + IP + keyword, got ${res.score}`);
}

// Test 4: Domain Spoofing - Hyphenated Affix (apple-support-helpline.com)
{
  console.log('\nTest 1.4: Domain Spoofing with Hyphens (http://apple-support-helpline.com/login)');
  const res = scanURL('http://apple-support-helpline.com/login');
  assertContract(res, 'urlScanner');
  assert(res.reasons.some(r => r.includes('Domain appears to spoof Apple')), 'Apple spoofing detected');
  assert(res.score >= 50, `Expected score >= 50, got ${res.score}`);
}

// Test 5: Domain Spoofing - Character Substitution (arnazon.com)
{
  console.log('\nTest 1.5: Typosquatting Character Substitution (http://arnazon.com/account/update)');
  const res = scanURL('http://arnazon.com/account/update');
  assertContract(res, 'urlScanner');
  assert(res.reasons.some(r => r.includes('Domain appears to spoof Amazon')), 'Amazon typosquatting detected');
}

// Test 6: Excessive Subdomains
{
  console.log('\nTest 1.6: Excessive Subdomains (https://login.verify.secure.portal.paypal.com.tk)');
  const res = scanURL('https://login.verify.secure.portal.paypal.com.tk');
  assertContract(res, 'urlScanner');
  assert(res.reasons.some(r => r.includes('Excessive subdomains detected in URL')), 'Excessive subdomains reason present');
}

// Test 7: Long URL (>100 characters)
{
  console.log('\nTest 1.7: Unusually Long URL (>100 chars)');
  const longUrl = 'https://example.com/portal/user/authentication/verify-credentials?token=abc1234567890abcdef1234567890abcdef1234567890&action=login';
  const res = scanURL(longUrl);
  assertContract(res, 'urlScanner');
  assert(res.metadata.urlLength > 100, 'URL length > 100');
  assert(res.reasons.some(r => r.includes('URL is unusually long')), 'Long URL reason present');
}

// Test 8: Edge Cases (empty / null / undefined / no protocol)
{
  console.log('\nTest 1.8: Edge Cases for urlScanner');
  const resEmpty = scanURL('');
  assertContract(resEmpty, 'urlScanner');
  assert(resEmpty.score === 0, 'Empty URL score is 0');

  const resNull = scanURL(null);
  assertContract(resNull, 'urlScanner');
  assert(resNull.score === 0, 'Null URL score is 0');

  const resUndefined = scanURL(undefined);
  assertContract(resUndefined, 'urlScanner');
  assert(resUndefined.score === 0, 'Undefined URL score is 0');

  const resNoProtocol = scanURL('paypa1-login.tk/verify');
  assertContract(resNoProtocol, 'urlScanner');
  assert(resNoProtocol.score >= 50, 'Missing protocol evaluated and penalized appropriately');
}

console.log('\n====================================================');
console.log('2. TESTING fileScanner.js');
console.log('====================================================\n');

// Test 1: Reference Example from Specification
{
  console.log('Test 2.1: Reference Double Extension (invoice.pdf.exe)');
  const res = scanFile('invoice.pdf.exe');
  assertContract(res, 'fileScanner');
  assert(res.score === 90, `Expected score 90, got ${res.score}`);
  assert(res.metadata.originalFilename === 'invoice.pdf.exe', 'originalFilename matches');
  assert(res.metadata.detectedExtension === '.exe', 'detectedExtension is .exe');
  assert(res.metadata.isDoubleExtension === true, 'isDoubleExtension is true');
  assert(res.metadata.fakeExtension === '.pdf', 'fakeExtension is .pdf');
  assert(res.metadata.realExtension === '.exe', 'realExtension is .exe');
  assert(res.metadata.extensionRiskLevel === 'Very High', 'extensionRiskLevel is Very High');
  assert(res.reasons.includes('Double extension detected — real extension is .exe'), 'Double extension reason present');
  assert(res.reasons.includes('Executable file disguised as PDF'), 'Disguise reason present');
  assert(res.reasons.includes('Very high risk extension: .exe'), 'Very high risk extension reason present');
  assert(res.reasons.includes('Social engineering filename: invoice'), 'Social engineering reason present');
}

// Test 2: Clean Document File
{
  console.log('\nTest 2.2: Clean Document File (report.docx)');
  const res = scanFile('report.docx');
  assertContract(res, 'fileScanner');
  assert(res.score === 0, `Clean file score should be 0, got ${res.score}`);
  assert(res.reasons.length === 0, 'Clean file reasons should be empty');
  assert(res.metadata.extensionRiskLevel === 'Low', 'Risk level should be Low');
  assert(res.metadata.isDoubleExtension === false, 'isDoubleExtension should be false');
}

// Test 3: Misleading System Filename (svchost.exe)
{
  console.log('\nTest 2.3: System File Mimicry (svchost.exe)');
  const res = scanFile('svchost.exe');
  assertContract(res, 'fileScanner');
  assert(res.score === 60, `Expected score 60 (40 + 20), got ${res.score}`);
  assert(res.reasons.some(r => r.includes('Misleading system filename')), 'System file reason present');
}

// Test 4: Extension and Name Mismatch (photo.exe)
{
  console.log('\nTest 2.4: Extension and Name Mismatch (photo.exe)');
  const res = scanFile('photo.exe');
  assertContract(res, 'fileScanner');
  assert(res.reasons.some(r => r.includes('Extension and name mismatch: name suggests media')), 'Mismatch reason present');
  assert(res.score >= 60, `Expected score >= 60, got ${res.score}`);
}

// Test 5: Document Name with Screensaver Extension (invoice.scr)
{
  console.log('\nTest 2.5: Document Name with Screensaver Extension (invoice.scr)');
  const res = scanFile('invoice.scr');
  assertContract(res, 'fileScanner');
  assert(res.reasons.some(r => r.includes('Extension and name mismatch: name suggests document')), 'Document/scr mismatch detected');
  assert(res.reasons.some(r => r.includes('Social engineering filename: invoice')), 'Social engineering keyword detected');
  assert(res.metadata.extensionRiskLevel === 'Very High', 'Risk level is Very High');
}

// Test 6: High Risk Script File (backup.sh, script.py)
{
  console.log('\nTest 2.6: High Risk Script File (backup.sh)');
  const res = scanFile('backup.sh');
  assertContract(res, 'fileScanner');
  assert(res.metadata.extensionRiskLevel === 'High', 'Risk level is High');
  assert(res.score === 25, `Expected score 25, got ${res.score}`);
  assert(res.reasons.includes('High risk extension: .sh'), 'High risk extension reason present');
}

// Test 7: Moderate Risk Archive (archive.zip)
{
  console.log('\nTest 2.7: Moderate Risk Archive (archive.zip)');
  const res = scanFile('archive.zip');
  assertContract(res, 'fileScanner');
  assert(res.metadata.extensionRiskLevel === 'Medium', 'Risk level is Medium');
  assert(res.score === 10, `Expected score 10, got ${res.score}`);
  assert(res.reasons.includes('Moderate risk extension: .zip'), 'Moderate risk reason present');
}

// Test 8: Excessive Spaces to Hide Extension ("invoice.pdf             .exe")
{
  console.log('\nTest 2.8: Excessive Spaces Obfuscation ("invoice.pdf             .exe")');
  const res = scanFile('invoice.pdf             .exe');
  assertContract(res, 'fileScanner');
  assert(res.reasons.some(r => r.includes('excessive spaces to hide extension')), 'Excessive spaces reason present');
  assert(res.score >= 90, `Expected high score >= 90, got ${res.score}`);
}

// Test 9: Unicode RTLO Spoofing ("photo\u202Efdp.exe")
{
  console.log('\nTest 2.9: Unicode RTLO Spoofing ("photo\\u202Efdp.exe")');
  const res = scanFile('photo\u202Efdp.exe');
  assertContract(res, 'fileScanner');
  assert(res.reasons.some(r => r.includes('suspicious Unicode lookalike or hidden characters')), 'Unicode spoofing reason present');
}

// Test 10: Edge Cases (empty, null, undefined, no extension, path prefixes)
{
  console.log('\nTest 2.10: Edge Cases for fileScanner');
  const resEmpty = scanFile('');
  assertContract(resEmpty, 'fileScanner');
  assert(resEmpty.score === 0, 'Empty filename score is 0');

  const resNull = scanFile(null);
  assertContract(resNull, 'fileScanner');
  assert(resNull.score === 0, 'Null filename score is 0');

  const resUndefined = scanFile(undefined);
  assertContract(resUndefined, 'fileScanner');
  assert(resUndefined.score === 0, 'Undefined filename score is 0');

  const resNoExt = scanFile('my_test_document');
  assertContract(resNoExt, 'fileScanner');
  assert(resNoExt.score === 0, 'File with no extension score is 0');

  const resWithPath = scanFile('/var/downloads/invoice.pdf.exe');
  assertContract(resWithPath, 'fileScanner');
  assert(resWithPath.score === 90, 'File with path prefix properly analyzed');
}

console.log('\n====================================================');
console.log(`TEST SUMMARY: ${passed} passed, ${failed} failed`);
console.log('====================================================');

if (failed > 0) {
  process.exit(1);
} else {
  console.log('\nAll tests passed successfully!\n');
}
