/**
 * Threat Detection Security Module — URL Scanner
 * Analyzes a URL string and detects signs of malicious intent, phishing attempts, or suspicious patterns.
 * 
 * Output Contract:
 * {
 *   score: number (0-100),
 *   reasons: string[],
 *   metadata: {
 *     protocol: string,
 *     domain: string,
 *     suspiciousKeywordsFound: string[],
 *     tldRiskLevel: "Low" | "Medium" | "High",
 *     isIPAddress: boolean,
 *     urlLength: number
 *   }
 * }
 */

// Top Level Domain Risk Categories
const HIGH_RISK_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', // Free domain TLDs
  '.xyz', '.top', '.click', '.loan', '.win'
]);

const MEDIUM_RISK_TLDS = new Set([
  '.info', '.biz'
]);

// Suspicious Keywords
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'secure', 'update',
  'account', 'banking', 'confirm', 'password',
  'free', 'winner', 'prize', 'click', 'lucky'
];

// Major Brands to Protect from Spoofing
const PROTECTED_BRANDS = [
  { name: 'PayPal', key: 'paypal', legitDomains: ['paypal.com', 'paypal.me'] },
  { name: 'Amazon', key: 'amazon', legitDomains: ['amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.co.jp', 'amazon.ca', 'amazon.in'] },
  { name: 'Google', key: 'google', legitDomains: ['google.com', 'google.co.uk', 'google.co.in', 'google.ca', 'google.de', 'google.fr'] },
  { name: 'Apple', key: 'apple', legitDomains: ['apple.com', 'icloud.com'] },
  { name: 'Microsoft', key: 'microsoft', legitDomains: ['microsoft.com', 'live.com', 'office.com', 'msn.com', 'outlook.com'] },
  { name: 'Netflix', key: 'netflix', legitDomains: ['netflix.com'] },
  { name: 'Facebook', key: 'facebook', legitDomains: ['facebook.com', 'fb.com'] }
];

// Character substitution / lookalike map for typosquatting detection
const CHAR_SUBSTITUTIONS = [
  [/1/g, 'l'],
  [/0/g, 'o'],
  [/rn/g, 'm'],
  [/vv/g, 'w'],
  [/5/g, 's'],
  [/3/g, 'e'],
  [/4/g, 'a'],
  [/@/g, 'a']
];

/**
 * Normalizes a domain string by converting common visual substitutions
 */
function normalizeLookalikes(str) {
  let normalized = str.toLowerCase();
  for (const [pattern, replacement] of CHAR_SUBSTITUTIONS) {
    normalized = normalized.replace(pattern, replacement);
  }
  return normalized;
}

/**
 * Computes Levenshtein distance between two strings
 */
function levenshtein(a, b) {
  const matrix = [];
  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }
  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1, // substitution
          matrix[i][j - 1] + 1,     // insertion
          matrix[i - 1][j] + 1      // deletion
        );
      }
    }
  }
  return matrix[b.length][a.length];
}

/**
 * Validates whether a hostname is an IPv4 or IPv6 address
 */
function checkIsIPAddress(hostname) {
  if (!hostname) return false;
  // IPv4 check
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const match = hostname.match(ipv4Regex);
  if (match) {
    for (let i = 1; i <= 4; i++) {
      const octet = parseInt(match[i], 10);
      if (octet < 0 || octet > 255) return false;
    }
    return true;
  }
  // IPv6 check
  if (hostname.includes(':')) {
    const cleanIPv6 = hostname.replace(/^\[|\]$/g, '');
    return /^[0-9a-fA-F:]+$/.test(cleanIPv6) && cleanIPv6.split(':').length >= 3;
  }
  return false;
}

/**
 * Scans a URL string and calculates a threat risk score with reasons and metadata.
 * 
 * @param {string} url - The URL to analyze
 * @returns {{ score: number, reasons: string[], metadata: object }}
 */
export function scanURL(url) {
  // Edge case: empty or invalid input
  if (!url || typeof url !== 'string' || url.trim().length === 0) {
    return {
      score: 0,
      reasons: ['No URL provided for analysis'],
      metadata: {
        protocol: '',
        domain: '',
        suspiciousKeywordsFound: [],
        tldRiskLevel: 'Low',
        isIPAddress: false,
        urlLength: 0
      }
    };
  }

  const rawUrl = url.trim();
  const urlLength = rawUrl.length;
  let score = 0;
  const reasons = [];

  // 1. Protocol Detection & HTTPS Check
  let protocol = 'http';
  let hasProtocolSpecified = false;

  if (/^https:\/\//i.test(rawUrl)) {
    protocol = 'https';
    hasProtocolSpecified = true;
  } else if (/^http:\/\//i.test(rawUrl)) {
    protocol = 'http';
    hasProtocolSpecified = true;
    score += 15;
    reasons.push('URL uses HTTP — not secure');
  } else if (/^[a-zA-Z]+:\/\//i.test(rawUrl)) {
    const schemeMatch = rawUrl.match(/^([a-zA-Z]+):\/\//);
    protocol = schemeMatch ? schemeMatch[1].toLowerCase() : 'unknown';
    hasProtocolSpecified = true;
    if (protocol !== 'https') {
      score += 15;
      reasons.push(`URL uses unencrypted protocol (${protocol}) — not secure`);
    }
  } else {
    protocol = 'http';
    score += 15;
    reasons.push('URL uses HTTP — not secure');
  }

  // 2. Parse URL Components
  let parsedUrl = null;
  let hostname = '';
  let pathname = '';
  let search = '';

  try {
    const parseTarget = hasProtocolSpecified ? rawUrl : `http://${rawUrl}`;
    parsedUrl = new URL(parseTarget);
    hostname = parsedUrl.hostname.toLowerCase();
    pathname = parsedUrl.pathname.toLowerCase();
    search = parsedUrl.search.toLowerCase();
  } catch {
    const match = rawUrl.match(/^(?:[a-zA-Z]+:\/\/)?([^\/\?#:]+)(?::\d+)?(\/[^\?#]*)?(\?[^#]*)?/);
    if (match) {
      hostname = (match[1] || '').toLowerCase();
      pathname = (match[2] || '').toLowerCase();
      search = (match[3] || '').toLowerCase();
    }
  }

  const domain = hostname;

  // 3. IP Address Check
  const isIPAddress = checkIsIPAddress(hostname);
  if (isIPAddress) {
    score += 30;
    reasons.push('IP address used instead of domain name');
  }

  // 4. Domain Spoofing Detection
  let domainSpoofingDetected = false;

  if (!isIPAddress && hostname) {
    for (const brand of PROTECTED_BRANDS) {
      const isLegit = brand.legitDomains.some(legit => 
        hostname === legit || hostname.endsWith('.' + legit)
      );

      if (isLegit) {
        continue;
      }

      const normalizedHost = normalizeLookalikes(hostname);
      const hostTokens = hostname.split(/[\.-]/);

      let brandFoundInDomain = false;

      // Check normalized lookalikes (e.g. paypa1, g00gle)
      if (normalizedHost.includes(brand.key)) {
        brandFoundInDomain = true;
      }

      // Check token edit distance (e.g. arnazon)
      if (!brandFoundInDomain) {
        for (const token of hostTokens) {
          if (token.length >= 4 && levenshtein(token, brand.key) <= 1) {
            brandFoundInDomain = true;
            break;
          }
        }
      }

      // Check hyphenated extra words (e.g. apple-support-helpline, paypal-secure)
      if (!brandFoundInDomain) {
        if (hostname.includes(brand.key + '-') || hostname.includes('-' + brand.key)) {
          brandFoundInDomain = true;
        }
      }

      if (brandFoundInDomain) {
        domainSpoofingDetected = true;
        score += 30;
        reasons.push(`Domain appears to spoof ${brand.name}`);
        break;
      }
    }
  }

  // 5. TLD Risk Level
  let tldRiskLevel = 'Low';
  let tld = '';
  if (!isIPAddress && hostname.includes('.')) {
    const lastDotIndex = hostname.lastIndexOf('.');
    tld = hostname.slice(lastDotIndex).toLowerCase();

    if (HIGH_RISK_TLDS.has(tld)) {
      tldRiskLevel = 'High';
      score += 25;
      reasons.push(`High risk TLD detected: ${tld}`);
    } else if (MEDIUM_RISK_TLDS.has(tld)) {
      tldRiskLevel = 'Medium';
      score += 15;
      reasons.push(`Moderate risk TLD detected: ${tld}`);
    }
  }

  // 6. Suspicious Keyword Detection
  const foundKeywordsMap = new Map();
  const keywordsToScan = [...SUSPICIOUS_KEYWORDS];

  for (const brand of PROTECTED_BRANDS) {
    const isLegit = brand.legitDomains.some(legit => 
      hostname === legit || hostname.endsWith('.' + legit)
    );
    if (!isLegit && !keywordsToScan.includes(brand.key)) {
      keywordsToScan.push(brand.key);
    }
  }

  const domainTokens = hostname ? hostname.split(/[\.-]/).filter(Boolean) : [];
  const pathTokens = pathname ? pathname.split(/[\/\-_\.]/).filter(Boolean) : [];
  const lowerUrl = rawUrl.toLowerCase();

  for (const kw of keywordsToScan) {
    const inDomain = domainTokens.includes(kw) || domainTokens.some(tok => tok.includes(kw) && tok !== kw && tok.length - kw.length <= 4);
    const inPath = pathTokens.includes(kw) || pathTokens.some(tok => tok.includes(kw));

    if (inDomain || inPath) {
      // Find earliest appearance index for sorting
      const pos = lowerUrl.indexOf(kw);
      foundKeywordsMap.set(kw, pos >= 0 ? pos : 9999);
    }
  }

  // Sort keywords by order of appearance in URL
  const suspiciousKeywordsFound = Array.from(foundKeywordsMap.entries())
    .sort((a, b) => a[1] - b[1])
    .map(entry => entry[0]);

  if (suspiciousKeywordsFound.length > 0) {
    reasons.push(`Suspicious keywords found: ${suspiciousKeywordsFound.join(', ')}`);

    if (domainSpoofingDetected) {
      const pathKeywords = suspiciousKeywordsFound.filter(kw => 
        pathTokens.includes(kw) || pathTokens.some(tok => tok.includes(kw))
      );
      const externalCount = Math.max(pathKeywords.length, 1);
      score += externalCount * 10;
    } else {
      score += suspiciousKeywordsFound.length * 10;
    }
  }

  // 7. URL Length and Complexity Check
  if (urlLength > 100) {
    score += 10;
    reasons.push('URL is unusually long (over 100 characters)');
  }

  // Excessive subdomains
  if (!isIPAddress && hostname) {
    const parts = hostname.split('.');
    if (parts.length > 4) {
      score += 20;
      reasons.push('Excessive subdomains detected in URL');
    }
  }

  // Excessive special characters
  const specialCharsMatch = rawUrl.match(/[@%=&]/g);
  if (rawUrl.includes('@') || (specialCharsMatch && specialCharsMatch.length >= 4)) {
    score += 10;
    reasons.push('Excessive or suspicious special characters detected in URL');
  }

  // 8. Path and Parameter Analysis
  const suspiciousPathRegex = /\/(?:admin|wp-admin|passwd|login|config|\.env)(?:\/|$|\.|\?)/i;
  if (suspiciousPathRegex.test(pathname)) {
    score += 10;
    reasons.push(`Suspicious path detected in URL: ${pathname}`);
  }

  // Redirect parameter detection
  const redirectParamRegex = /(?:[?&])(?:redirect|url|next|return|goto|r|target)=(?:https?%3A%2F%2F|https?:\/\/|[^\s&]+)/i;
  let hasRedirect = redirectParamRegex.test(rawUrl);

  if (!hasRedirect && parsedUrl && parsedUrl.searchParams) {
    const redirectKeys = ['redirect', 'url', 'next', 'return', 'goto', 'r', 'target'];
    for (const key of redirectKeys) {
      if (parsedUrl.searchParams.has(key)) {
        hasRedirect = true;
        break;
      }
    }
  }

  if (hasRedirect) {
    score += 15;
    reasons.push('Redirect parameter detected in URL');
  }

  // Cap score between 0 and 100
  const finalScore = Math.min(100, Math.max(0, score));

  return {
    score: finalScore,
    reasons,
    metadata: {
      protocol,
      domain,
      suspiciousKeywordsFound,
      tldRiskLevel,
      isIPAddress,
      urlLength
    }
  };
}

// CLI execution support: node urlScanner.js "https://your-url.com"
if (process.argv[1] && process.argv[1].endsWith('urlScanner.js') && process.argv[2]) {
  const result = scanURL(process.argv[2]);
  console.log(JSON.stringify(result, null, 2));
}
