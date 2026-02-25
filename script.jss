function loadExample(url) {
  document.getElementById('urlInput').value = url;
  analyze();
}

function extractFeatures(url) {
  let parsed;
  try { parsed = new URL(url); } catch(e) { parsed = null; }

  const hostname = parsed ? parsed.hostname : url;
  const path = parsed ? parsed.pathname + parsed.search : '';
  const fullUrl = url;

  const features = {};

  // URL length
  features.urlLength = fullUrl.length;

  // Number of dots
  features.dotCount = (hostname.match(/\./g) || []).length;

  // Has HTTPS
  features.hasHttps = parsed ? parsed.protocol === 'https:' : false;

  // IP-based URL
  features.isIpBased = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);

  // Has @ symbol
  features.hasAt = fullUrl.includes('@');

  // Has double slash
  features.hasDoubleSlash = /\/\/.*\/\//.test(fullUrl);

  // Suspicious TLD
  const suspTLDs = ['xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'click', 'download'];
  const tld = hostname.split('.').pop().toLowerCase();
  features.suspiciousTLD = suspTLDs.includes(tld);

  // Suspicious keywords
  const suspKeywords = ['login', 'verify', 'secure', 'update', 'account', 'bank', 'paypal', 'ebay', 'amazon', 'signin', 'password', 'confirm'];
  features.suspiciousKeywords = suspKeywords.filter(k => fullUrl.toLowerCase().includes(k));

  // Hyphen count in domain
  features.hyphenCount = (hostname.match(/-/g) || []).length;

  // Subdomain count
  const parts = hostname.split('.');
  features.subdomainCount = Math.max(0, parts.length - 2);

  // Special chars count
  features.specialCharCount = (fullUrl.match(/[!@#$%^&*()+=\[\]{};':"\\|,<>\?]/g) || []).length;

  // URL entropy (complexity)
  const chars = {};
  for (const c of fullUrl) chars[c] = (chars[c] || 0) + 1;
  const len = fullUrl.length;
  let entropy = 0;
  for (const k in chars) {
    const p = chars[k] / len;
    entropy -= p * Math.log2(p);
  }
  features.entropy = Math.round(entropy * 100) / 100;

  return features;
}

function scoreURL(features) {
  let score = 0;
  const threats = [];

  if (features.urlLength > 75) {
    score += 15;
    threats.push({ level: 'warn', icon: '📏', title: 'Long URL', desc: `URL length is ${features.urlLength} characters. Phishing URLs are often unusually long to obscure the real destination.` });
  }

  if (!features.hasHttps) {
    score += 20;
    threats.push({ level: 'danger', icon: '🔓', title: 'No HTTPS Encryption', desc: 'Connection is not encrypted. Legitimate services almost always use HTTPS.' });
  }

  if (features.isIpBased) {
    score += 30;
    threats.push({ level: 'danger', icon: '🔢', title: 'IP-Based URL', desc: 'URL uses a raw IP address instead of a domain name. This is a common phishing tactic.' });
  }

  if (features.hasAt) {
    score += 25;
    threats.push({ level: 'danger', icon: '⚠️', title: '@  Symbol Detected', desc: 'The @ symbol in URLs can redirect to a malicious host while displaying a legitimate-looking prefix.' });
  }

  if (features.suspiciousTLD) {
    score += 20;
    threats.push({ level: 'danger', icon: '🚩', title: 'Suspicious TLD', desc: 'This domain uses a top-level domain commonly associated with free/throwaway domains used in phishing.' });
  }

  if (features.suspiciousKeywords.length > 0) {
    score += Math.min(features.suspiciousKeywords.length * 8, 25);
    threats.push({ level: 'warn', icon: '🔑', title: 'Suspicious Keywords', desc: `Found keywords: ${features.suspiciousKeywords.join(', ')}. These terms frequently appear in credential phishing attacks.` });
  }

  if (features.hyphenCount > 2) {
    score += 10;
    threats.push({ level: 'warn', icon: '➖', title: 'Excessive Hyphens', desc: `${features.hyphenCount} hyphens in domain. Attackers use hyphens to create misleading domain names (e.g. paypal-secure-login.xyz).` });
  }

  if (features.subdomainCount > 2) {
    score += 10;
    threats.push({ level: 'warn', icon: '🌐', title: 'Deep Subdomain Chain', desc: `${features.subdomainCount} subdomains detected. This is sometimes used to make URLs look more legitimate.` });
  }

  if (features.dotCount > 4) {
    score += 8;
    threats.push({ level: 'warn', icon: '•••', title: 'Excessive Dots', desc: `${features.dotCount} dots in URL. High dot counts can indicate URL obfuscation attempts.` });
  }

  score = Math.min(score, 100);

  // Simulate ML probability
  const noise = (Math.random() - 0.5) * 8;
  const mlMalProb = Math.min(100, Math.max(0, score * 0.85 + noise + (threats.length * 2)));
  const mlSafeProb = 100 - mlMalProb;

  return { score, threats, mlMalProb: Math.round(mlMalProb), mlSafeProb: Math.round(mlSafeProb) };
}

function getVerdict(score) {
  if (score < 20) return { label: '✅ Safe', color: 'var(--safe)', tag: 'safe' };
  if (score < 50) return { label: '⚠️ Suspicious', color: 'var(--warn)', tag: 'warn' };
  return { label: '🚨 Malicious', color: 'var(--accent2)', tag: 'danger' };
}

function analyze() {
  const url = document.getElementById('urlInput').value.trim();
  if (!url) return;

  const loading = document.getElementById('loading');
  const resultCard = document.getElementById('resultCard');

  resultCard.classList.remove('visible');
  loading.classList.add('visible');

  setTimeout(() => {
    const features = extractFeatures(url);
    const { score, threats, mlMalProb, mlSafeProb } = scoreURL(features);
    const verdict = getVerdict(score);

    loading.classList.remove('visible');
    renderResult(url, features, score, threats, mlMalProb, mlSafeProb, verdict);
    resultCard.classList.add('visible');
  }, 900);
}

function renderResult(url, features, score, threats, mlMalProb, mlSafeProb, verdict) {
  // Risk arc
  const arc = document.getElementById('riskArc');
  const circumference = 289;
  const offset = circumference - (score / 100) * circumference;
  arc.style.stroke = verdict.color;
  arc.style.strokeDashoffset = offset;

  // Risk text
  const pctEl = document.getElementById('riskPct');
  pctEl.textContent = score + '%';
  pctEl.style.color = verdict.color;

  document.getElementById('riskVerdict').innerHTML = `<span style="color:${verdict.color}">${verdict.label}</span>`;
  document.getElementById('riskUrl').textContent = url.length > 65 ? url.substring(0, 62) + '...' : url;

  // Tags
  const tagsEl = document.getElementById('riskTags');
  tagsEl.innerHTML = '';
  const tags = [];
  if (features.hasHttps) tags.push({ label: 'HTTPS', cls: 'tag-safe' });
  else tags.push({ label: 'HTTP', cls: 'tag-danger' });
  if (features.isIpBased) tags.push({ label: 'IP-BASED', cls: 'tag-danger' });
  if (features.suspiciousTLD) tags.push({ label: 'SUSPICIOUS TLD', cls: 'tag-danger' });
  if (features.suspiciousKeywords.length) tags.push({ label: 'PHISH KEYWORDS', cls: 'tag-warn' });
  if (score < 20) tags.push({ label: 'CLEAN', cls: 'tag-safe' });
  tags.forEach(t => {
    tagsEl.innerHTML += `<span class="risk-tag ${t.cls}">${t.label}</span>`;
  });

  // Features grid
  const grid = document.getElementById('featuresGrid');
  const featureItems = [
    { name: 'URL Length', val: features.urlLength + ' chars', status: features.urlLength > 75 ? 'warn' : 'safe' },
    { name: 'HTTPS', val: features.hasHttps ? 'Yes ✓' : 'No ✗', status: features.hasHttps ? 'safe' : 'danger' },
    { name: 'IP-Based URL', val: features.isIpBased ? 'Yes ✗' : 'No ✓', status: features.isIpBased ? 'danger' : 'safe' },
    { name: 'Dot Count', val: features.dotCount, status: features.dotCount > 4 ? 'warn' : 'safe' },
    { name: 'Suspicious TLD', val: features.suspiciousTLD ? 'Yes ✗' : 'No ✓', status: features.suspiciousTLD ? 'danger' : 'safe' },
    { name: 'Keyword Hits', val: features.suspiciousKeywords.length, status: features.suspiciousKeywords.length > 0 ? 'warn' : 'safe' },
    { name: 'Hyphens in Domain', val: features.hyphenCount, status: features.hyphenCount > 2 ? 'warn' : 'safe' },
    { name: 'URL Entropy', val: features.entropy, status: features.entropy > 4.5 ? 'warn' : 'safe' },
  ];

  grid.innerHTML = featureItems.map(f => {
    const icons = { safe: '✓', warn: '!', danger: '✗' };
    const colors = { safe: 'var(--safe)', warn: 'var(--warn)', danger: 'var(--accent2)' };
    return `
      <div class="feature-item">
        <div class="feature-icon fi-${f.status}" style="color:${colors[f.status]}; font-family:var(--mono); font-size:12px; font-weight:700;">${icons[f.status]}</div>
        <div class="feature-info">
          <div class="feature-name">${f.name}</div>
          <div class="feature-val" style="color:${colors[f.status]}">${f.val}</div>
        </div>
      </div>`;
  }).join('');

  // ML bars
  document.getElementById('mlMalPct').textContent = mlMalProb + '%';
  document.getElementById('mlSafePct').textContent = mlSafeProb + '%';
  setTimeout(() => {
    document.getElementById('mlMalBar').style.width = mlMalProb + '%';
    document.getElementById('mlSafeBar').style.width = mlSafeProb + '%';
  }, 100);

  // Threats
  const threatsList = document.getElementById('threatsList');
  const threatsTitle = document.getElementById('threatsTitle');
  if (threats.length === 0) {
    threatsTitle.textContent = '✅ No Threat Indicators Detected';
    threatsList.innerHTML = '<div class="threat-item"><span class="threat-icon">🟢</span><div class="threat-text"><strong>URL appears safe</strong><p>No significant security indicators found. The URL follows standard patterns and uses secure connection.</p></div></div>';
  } else {
    threatsTitle.textContent = `Detected Threat Indicators (${threats.length})`;
    threatsList.innerHTML = threats.map(t => {
      const colors = { safe: 'var(--safe)', warn: 'var(--warn)', danger: 'var(--accent2)' };
      return `<div class="threat-item">
        <span class="threat-icon">${t.icon}</span>
        <div class="threat-text">
          <strong style="color:${colors[t.level]}">${t.title}</strong>
          <p>${t.desc}</p>
        </div>
      </div>`;
    }).join('');
  }
}

// Enter key
document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') analyze();
});
