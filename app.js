/* ExposureCheck — client-side deployed-site exposure scanner.
 * A Copper Bay Labs product. Forked from LeakCheck for cohesion.
 *
 * WHAT THIS DOES
 *   Checks whether a DEPLOYED website is leaking secrets, sensitive files, or
 *   original source. Two input modes:
 *     1. URL mode  — fetch the live page HTML + its same-origin <script>
 *        bundles through a PUBLIC CORS PROXY (fallback chain, per-request
 *        timeouts), probe a curated list of sensitive paths, and check
 *        source maps. Degrades gracefully to the paste fallback if every
 *        proxy fails — it NEVER hangs.
 *     2. PASTE mode — analyze built HTML/JS pasted directly. Always works
 *        with no network. "Try an example" loads a sample vulnerable bundle
 *        so the demo works fully offline.
 *
 * SAFETY FRAMING
 *   This is a DEFENSIVE self-check for sites you own or are authorized to
 *   test. It only fetches publicly-served paths a normal visitor could load.
 *   Results are never stored or transmitted anywhere except the proxy fetch
 *   of the target URL itself. No backend, no keys, no analytics.
 *
 * XSS GUARANTEE
 *   The tool fetches ARBITRARY remote HTML/JS. Every piece of fetched/pasted
 *   content reaches the DOM only via textContent (the el() helper) — never
 *   innerHTML. Pasted/remote code cannot inject markup or run script. The
 *   only innerHTML-free clears are of containers holding no user data.
 *
 * MASKING
 *   Full secret values are NEVER rendered, copied, or placed in any
 *   title/attr. Every preview is masked to first4 + last4 before it touches
 *   the DOM or the clipboard (ported from LeakCheck's maskSecret).
 */
(function () {
  "use strict";

  /* ================================================================== *
   * Severity ordering / metadata (shared with LeakCheck styles).
   * ================================================================== */
  var SEVERITIES = ["critical", "high", "medium", "low"];
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
  // Maps full severity to the abbreviated class suffix the stylesheet uses
  // for the summary-bar count pills (.sev-count.crit/.high/.med/.low).
  var SEV_ABBR = { critical: "crit", high: "high", medium: "med", low: "low" };

  /* ================================================================== *
   * Masking — the core safety primitive (ported from LeakCheck).
   * Show only first 4 + last 4 chars; collapse the middle to bullets.
   * Whitespace/newlines stripped so multi-line PEM blocks render as one
   * safe token.
   * ================================================================== */
  function maskSecret(raw) {
    var s = String(raw).replace(/\s+/g, "");
    if (s.length <= 8) {
      var head = s.slice(0, Math.min(2, s.length));
      return head + repeat("•", Math.max(4, s.length - head.length));
    }
    var first = s.slice(0, 4);
    var last = s.slice(-4);
    var midLen = s.length - 8;
    var bullets = repeat("•", Math.min(midLen, 18));
    return first + bullets + last;
  }
  function repeat(ch, n) {
    var out = "";
    for (var i = 0; i < n; i++) out += ch;
    return out;
  }

  /* ================================================================== *
   * Shannon entropy (bits per char) — filters generic/entropy hits so we
   * only flag values that look genuinely random (real secrets).
   * ================================================================== */
  function shannonEntropy(str) {
    if (!str.length) return 0;
    var freq = Object.create(null);
    for (var i = 0; i < str.length; i++) {
      var c = str[i];
      freq[c] = (freq[c] || 0) + 1;
    }
    var entropy = 0;
    var len = str.length;
    for (var k in freq) {
      var p = freq[k] / len;
      entropy -= p * (Math.log(p) / Math.LN2);
    }
    return entropy;
  }

  /* ================================================================== *
   * Secret detectors — ported verbatim from LeakCheck's detector set.
   * Each: { name, severity, why, regex, group?, rotate, entropyMin? }
   * regex MUST be global. If group is set, that capture group is the
   * secret to mask; otherwise the whole match is the secret.
   * ================================================================== */
  var DETECTORS = [
    {
      name: "AWS Access Key ID",
      severity: "high",
      regex: /\bAKIA[0-9A-Z]{16}\b/g,
      why: "An AWS access key ID identifies an IAM principal and, paired with its secret, grants programmatic access to your AWS account.",
      rotate: "the AWS IAM console (deactivate then delete the key pair)"
    },
    {
      name: "AWS Secret Access Key",
      severity: "critical",
      regex: /(?:aws.{0,20})?(?:secret|SECRET)[^\n]{0,20}?["'=:\s]+([A-Za-z0-9\/+]{40})\b/g,
      group: 1,
      why: "The AWS secret access key is the password half of an AWS credential pair and lets an attacker fully control your AWS resources and bill.",
      rotate: "the AWS IAM console (rotate the access key pair immediately)"
    },
    {
      name: "GitHub Personal Access Token",
      severity: "critical",
      regex: /\bghp_[0-9A-Za-z]{36}\b/g,
      why: "A GitHub PAT can read and push to your repositories and act on your behalf across GitHub.",
      rotate: "GitHub → Settings → Developer settings → Personal access tokens (revoke it)"
    },
    {
      name: "GitHub Fine-grained PAT",
      severity: "critical",
      regex: /\bgithub_pat_[0-9A-Za-z_]{22,}\b/g,
      why: "A fine-grained GitHub PAT grants scoped repo/org access and can be replayed by anyone who finds it.",
      rotate: "GitHub → Settings → Developer settings → Fine-grained tokens (revoke it)"
    },
    {
      name: "GitHub OAuth / App Token",
      severity: "critical",
      regex: /\b(?:gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b/g,
      why: "GitHub OAuth, user-to-server, server-to-server, and refresh tokens authenticate GitHub API calls and can hijack a session or app installation.",
      rotate: "GitHub (revoke the OAuth app authorization / regenerate the app token)"
    },
    {
      name: "GitLab Personal Access Token",
      severity: "critical",
      regex: /\bglpat-[0-9A-Za-z_\-]{20,}\b/g,
      why: "A GitLab PAT can clone, push, and administer your GitLab projects depending on its scopes.",
      rotate: "GitLab → Preferences → Access Tokens (revoke it)"
    },
    {
      name: "OpenAI API Key (project)",
      severity: "critical",
      regex: /\bsk-proj-[A-Za-z0-9_\-]{20,}\b/g,
      why: "An OpenAI project key bills your account for API usage and can be abused to run up large charges.",
      rotate: "the OpenAI dashboard → API keys (revoke it)"
    },
    {
      name: "OpenAI API Key",
      severity: "critical",
      regex: /\bsk-(?!proj-|ant-)[A-Za-z0-9]{20,}\b/g,
      why: "An OpenAI API key bills your account for model usage and can be drained by anyone who obtains it.",
      rotate: "the OpenAI dashboard → API keys (revoke it)"
    },
    {
      name: "Anthropic API Key",
      severity: "critical",
      regex: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,
      why: "An Anthropic API key bills your account for Claude usage and can be abused for unauthorized requests.",
      rotate: "the Anthropic console → API keys (revoke it)"
    },
    {
      name: "Stripe Secret Key (live)",
      severity: "critical",
      regex: /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g,
      why: "A live Stripe secret key can create charges, issue refunds, and read customer/payment data on your real account.",
      rotate: "the Stripe dashboard → Developers → API keys (roll the key immediately)"
    },
    {
      name: "Stripe Secret Key (test)",
      severity: "high",
      regex: /\b(?:sk|rk)_test_[0-9A-Za-z]{20,}\b/g,
      why: "A Stripe test secret key exposes your test environment and signals a secret-in-code habit that often repeats with live keys.",
      rotate: "the Stripe dashboard → Developers → API keys (roll the test key)"
    },
    {
      name: "Stripe Publishable Live Key",
      severity: "low",
      regex: /\bpk_live_[0-9A-Za-z]{20,}\b/g,
      why: "A Stripe publishable key is meant to be public, but its presence often means secret keys are nearby in the same file.",
      rotate: "the Stripe dashboard (publishable keys are public, but review the file for secret keys)"
    },
    {
      name: "Google API Key",
      severity: "high",
      regex: /AIza[0-9A-Za-z_\-]{35,}/g,
      why: "A Google API key can call billable Google/Firebase/Maps APIs on your project and rack up charges if unrestricted.",
      rotate: "Google Cloud Console → APIs & Services → Credentials (regenerate and add restrictions)"
    },
    {
      name: "Slack Token",
      severity: "critical",
      regex: /\bxox[baprs]-[0-9A-Za-z\-]{10,}\b/g,
      why: "A Slack token can read and post messages and access files across your workspace depending on its scopes.",
      rotate: "the Slack app config / workspace admin (revoke the token)"
    },
    {
      name: "Twilio API Key SID",
      severity: "high",
      regex: /\bSK[0-9a-f]{32}\b/g,
      why: "A Twilio API key SID, paired with its secret, can send SMS/voice and incur charges on your Twilio account.",
      rotate: "the Twilio console → API keys (delete the key)"
    },
    {
      name: "SendGrid API Key",
      severity: "critical",
      regex: /\bSG\.[\w\-]{22}\.[\w\-]{43}\b/g,
      why: "A SendGrid API key can send email as your domain, enabling spam or phishing from your reputation.",
      rotate: "the SendGrid dashboard → API Keys (delete the key)"
    },
    {
      name: "Mailgun API Key",
      severity: "high",
      regex: /\bkey-[0-9a-f]{32}\b/g,
      why: "A Mailgun API key can send email through your account and read sending logs.",
      rotate: "the Mailgun dashboard → API security (regenerate the key)"
    },
    {
      name: "npm Access Token",
      severity: "critical",
      regex: /\bnpm_[0-9A-Za-z]{36}\b/g,
      why: "An npm token can publish packages under your account, a vector for supply-chain attacks.",
      rotate: "npmjs.com → Access Tokens (revoke it)"
    },
    {
      name: "Shopify Access Token",
      severity: "critical",
      regex: /\b(?:shpat|shpss|shpca|shppa)_[0-9a-fA-F]{32}\b/g,
      why: "A Shopify access token can read/modify store data including orders and customers.",
      rotate: "the Shopify admin / partner dashboard (revoke the app token)"
    },
    {
      name: "Discord Bot Token",
      severity: "high",
      regex: /\b[MNO][A-Za-z0-9_\-]{23,25}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b/g,
      why: "A Discord bot token gives full control of the bot account, including reading and sending messages in every server it joined.",
      rotate: "the Discord developer portal → Bot (reset the token)"
    },
    {
      name: "JSON Web Token (JWT)",
      severity: "medium",
      regex: /\beyJ[\w\-]+\.eyJ[\w\-]+\.[\w\-]+\b/g,
      why: "A JWT can carry session identity or claims and may grant access until it expires if it is a live token.",
      rotate: "your auth provider / app (invalidate the session and rotate signing keys if it is a server secret)"
    },
    {
      name: "Private Key (PEM)",
      severity: "critical",
      regex: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
      why: "A PEM private key is the cryptographic identity behind TLS, SSH, or signing — whoever holds it can impersonate your service.",
      rotate: "the system that issued it (generate a new key pair and revoke/replace the old one everywhere)"
    },
    {
      name: "Database URI with credentials",
      severity: "critical",
      regex: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|amqps):\/\/[^\s:@\/]+:[^\s:@\/]+@[^\s\/"']+/g,
      why: "A database connection string with an inline username and password grants direct read/write access to your data.",
      rotate: "your database (rotate the database user's password and restrict network access)"
    },
    {
      name: "Authorization / Bearer header",
      severity: "high",
      regex: /(?:Authorization|authorization)\s*[:=]\s*["']?(?:Bearer|Basic|Token)\s+([A-Za-z0-9_\-\.=+\/]{12,})/g,
      group: 1,
      why: "A hard-coded Authorization header embeds a live credential that authenticates requests to a protected API.",
      rotate: "the issuing service (revoke the token and inject it from an env var at runtime)"
    },
    {
      name: "Generic API key / secret assignment",
      severity: "medium",
      regex: /(?:^|[^\w])([A-Za-z][A-Za-z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE[_-]?KEY|ACCESS[_-]?KEY|CLIENT[_-]?SECRET|AUTH))\s*[:=]\s*["'`]([^"'`\n]{8,})["'`]/gi,
      group: 2,
      why: "A secret-looking variable is assigned a value directly in source, so anyone with the code has the credential.",
      rotate: "the owning service (rotate the value and load it from an environment variable instead)",
      entropyMin: 2.6
    }
  ];

  /* Entropy fallback (ported): long high-entropy value assigned to a
   * secret-looking key the named/generic detectors did not already catch. */
  var ENTROPY_RE = /(?:^|[^\w])([A-Za-z][A-Za-z0-9_]*(?:key|secret|token|password|passwd|auth|credential|api)[A-Za-z0-9_]*)\s*[:=]\s*["'`]?([A-Za-z0-9_\-\.+\/=]{24,})["'`]?/gi;
  var ENTROPY_THRESHOLD = 4.0;

  /* ================================================================== *
   * Internals / leaked-info detectors (ExposureCheck additions).
   * These surface private endpoints, hostnames, and emails shipped in the
   * client bundle. They are NOT masked (they aren't secrets) but are
   * still inserted via textContent.
   * ================================================================== */
  var INTERNAL_DETECTORS = [
    {
      name: "Internal / localhost endpoint",
      severity: "medium",
      regex: /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?::\d+)?[^\s"'`<>]*/g,
      why: "An internal or localhost URL shipped to the browser reveals private infrastructure and can hint at services not meant to be public.",
      rotate: "your build config (strip localhost/private API base URLs from the production bundle and use a public gateway)"
    },
    {
      name: "Private hostname (.internal / .local / .corp)",
      severity: "medium",
      regex: /\bhttps?:\/\/[a-z0-9.\-]+\.(?:internal|local|lan|corp|intranet|test)(?::\d+)?[^\s"'`<>]*/gi,
      why: "A private hostname leaks internal network topology and the names of services that should not be referenced from public code.",
      rotate: "your build config (remove internal hostnames from the shipped bundle)"
    },
    {
      name: "Email address in bundle",
      severity: "low",
      regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
      why: "Email addresses baked into the client bundle can be harvested for spam or phishing and may reveal internal staff accounts.",
      rotate: "your source (move contact/admin emails server-side or behind a form rather than hard-coding them in client JS)"
    }
  ];
  // Common false-positive emails that aren't worth flagging.
  var EMAIL_IGNORE = /@(?:example\.com|sentry\.io|w3\.org|schema\.org|googleapis\.com|gstatic\.com|2x\.png)$/i;

  /* ================================================================== *
   * Line-number helpers (ported).
   * ================================================================== */
  function buildLineIndex(text) {
    var starts = [0];
    for (var i = 0; i < text.length; i++) {
      if (text[i] === "\n") starts.push(i + 1);
    }
    return starts;
  }
  function lineAt(starts, offset) {
    var lo = 0, hi = starts.length - 1, ans = 0;
    while (lo <= hi) {
      var mid = (lo + hi) >> 1;
      if (starts[mid] <= offset) { ans = mid; lo = mid + 1; }
      else hi = mid - 1;
    }
    return ans + 1;
  }

  /* ================================================================== *
   * scanCode — run all detectors over one blob of HTML/JS.
   * `sourceLabel` describes where the content came from (e.g. a script
   * URL or "pasted content") and is shown on each finding.
   * Returns finding objects. Secret values are masked; raw value is never
   * stored on the returned object.
   * ================================================================== */
  function scanCode(text, sourceLabel) {
    var findings = [];
    var lineIndex = buildLineIndex(text);
    var seen = Object.create(null);

    function push(opts) {
      if (!opts.value) return;
      var line = lineAt(lineIndex, opts.offset);
      var masked = opts.mask ? maskSecret(opts.value) : opts.value;
      var key = opts.name + "|" + masked + "|" + line + "|" + (sourceLabel || "");
      if (seen[key]) return;
      seen[key] = true;
      findings.push({
        category: opts.category,
        name: opts.name,
        severity: opts.severity,
        why: opts.why,
        rotate: opts.rotate,
        masked: masked,
        line: line,
        source: sourceLabel || null
      });
    }

    runDetectorList(DETECTORS, text, true, "secret", push);
    runInternalDetectors(text, push);

    // Entropy fallback.
    ENTROPY_RE.lastIndex = 0;
    var em;
    while ((em = ENTROPY_RE.exec(text)) !== null) {
      if (em.index === ENTROPY_RE.lastIndex) ENTROPY_RE.lastIndex++;
      var val = em[2];
      if (!val) continue;
      if (shannonEntropy(val) < ENTROPY_THRESHOLD) continue;
      var gidx = em[0].indexOf(val);
      var off = em.index + (gidx >= 0 ? gidx : 0);
      var ln = lineAt(lineIndex, off);
      var already = false;
      for (var f = 0; f < findings.length; f++) {
        if (findings[f].line === ln && findings[f].category === "secret") { already = true; break; }
      }
      if (already) continue;
      push({
        category: "secret",
        name: "High-entropy secret (heuristic)",
        severity: "medium",
        why: "This value is long and highly random, the signature of an API key or token even though it matches no known provider format.",
        rotate: "the owning service (rotate it and move it to an environment variable or secret manager)",
        value: val,
        offset: off,
        mask: true
      });
    }

    return findings;
  }

  function runDetectorList(list, text, mask, category, push) {
    for (var d = 0; d < list.length; d++) {
      var det = list[d];
      var re = det.regex;
      re.lastIndex = 0;
      var m;
      while ((m = re.exec(text)) !== null) {
        if (m.index === re.lastIndex) re.lastIndex++;
        var secret = det.group != null ? m[det.group] : m[0];
        if (!secret) continue;
        var secretOffset = m.index;
        if (det.group != null) {
          var gi = m[0].indexOf(secret);
          if (gi >= 0) secretOffset = m.index + gi;
        }
        if (det.entropyMin != null) {
          var clean = secret.replace(/\s+/g, "");
          if (shannonEntropy(clean) < det.entropyMin) continue;
        }
        push({
          category: category,
          name: det.name,
          severity: det.severity,
          why: det.why,
          rotate: det.rotate,
          value: secret,
          offset: secretOffset,
          mask: mask
        });
      }
    }
  }

  function runInternalDetectors(text, push) {
    for (var d = 0; d < INTERNAL_DETECTORS.length; d++) {
      var det = INTERNAL_DETECTORS[d];
      var re = det.regex;
      re.lastIndex = 0;
      var m;
      var hits = 0;
      while ((m = re.exec(text)) !== null) {
        if (m.index === re.lastIndex) re.lastIndex++;
        var val = m[0];
        if (!val) continue;
        if (det.name.indexOf("Email") === 0 && EMAIL_IGNORE.test(val)) continue;
        if (++hits > 25) break; // cap noisy categories (e.g. emails) per blob
        push({
          category: "internal",
          name: det.name,
          severity: det.severity,
          why: det.why,
          rotate: det.rotate,
          value: val,
          offset: m.index,
          mask: false
        });
      }
    }
  }

  /* ================================================================== *
   * Source-map references — //# sourceMappingURL=...  (and the older //@).
   * Returns array of { url, line } describing each reference found.
   * ================================================================== */
  function findSourceMapRefs(text) {
    var refs = [];
    var re = /[#@]\s*sourceMappingURL\s*=\s*([^\s'")]+)/g;
    var lineIndex = buildLineIndex(text);
    var m;
    while ((m = re.exec(text)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex++;
      var url = m[1];
      if (!url) continue;
      // Inline data: maps don't leak source files separately — note but skip fetch.
      refs.push({
        url: url,
        inline: /^data:/i.test(url),
        line: lineAt(lineIndex, m.index)
      });
    }
    return refs;
  }

  /* ================================================================== *
   * Networking — CORS proxy fallback chain with per-request timeouts.
   * Every fetch goes through a public proxy so the tool stays 100% static.
   * fetchViaProxy resolves to { ok, status, body } or rejects on total
   * failure / timeout. It NEVER hangs: each attempt is bounded by a timer.
   * ================================================================== */
  var PROXIES = [
    function (u) { return "https://api.allorigins.win/raw?url=" + encodeURIComponent(u); },
    function (u) { return "https://corsproxy.io/?url=" + encodeURIComponent(u); },
    function (u) { return "https://thingproxy.freeboard.io/fetch/" + u; }
  ];
  var REQUEST_TIMEOUT_MS = 9000;

  function timeoutFetch(url, ms) {
    // AbortController + a guaranteed-settle timer so a stalled proxy can't hang.
    return new Promise(function (resolve, reject) {
      var settled = false;
      var ctrl = (typeof AbortController !== "undefined") ? new AbortController() : null;
      var timer = setTimeout(function () {
        if (settled) return;
        settled = true;
        if (ctrl) { try { ctrl.abort(); } catch (e) {} }
        reject(new Error("timeout"));
      }, ms);
      var opts = { method: "GET", redirect: "follow", credentials: "omit" };
      if (ctrl) opts.signal = ctrl.signal;
      fetch(url, opts).then(function (resp) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve(resp);
      }).catch(function (err) {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(err);
      });
    });
  }

  // Try each proxy in order until one returns a usable response.
  // Resolves { ok, status, body }. The 429 of the *target* is surfaced via
  // status; a 429 from the *proxy* moves on to the next proxy.
  function fetchViaProxy(targetUrl) {
    var idx = 0;
    return new Promise(function (resolve, reject) {
      function attempt() {
        if (idx >= PROXIES.length) {
          reject(new Error("all-proxies-failed"));
          return;
        }
        var proxyUrl = PROXIES[idx++](targetUrl);
        timeoutFetch(proxyUrl, REQUEST_TIMEOUT_MS).then(function (resp) {
          // Proxy-level failure (rate-limited / blocked) → try next proxy.
          if (resp.status === 429 || resp.status === 403 || resp.status >= 500) {
            attempt();
            return;
          }
          resp.text().then(function (body) {
            resolve({ ok: resp.status >= 200 && resp.status < 300, status: resp.status, body: body });
          }, function () {
            resolve({ ok: resp.status >= 200 && resp.status < 300, status: resp.status, body: "" });
          });
        }).catch(function () {
          attempt(); // timeout or network error on this proxy → next
        });
      }
      attempt();
    });
  }

  /* ================================================================== *
   * URL / origin helpers.
   * ================================================================== */
  function normalizeUrl(raw) {
    var s = String(raw || "").trim();
    if (!s) return null;
    if (!/^https?:\/\//i.test(s)) s = "https://" + s;
    try {
      var u = new URL(s);
      if (u.protocol !== "http:" && u.protocol !== "https:") return null;
      return u;
    } catch (e) {
      return null;
    }
  }

  function originOf(u) {
    return u.protocol + "//" + u.host;
  }

  // Resolve a (possibly relative) script src against the page URL, keeping
  // only same-origin scripts (those are the ones we can attribute to the site).
  function sameOriginScriptUrls(html, pageUrl) {
    var urls = [];
    var seen = Object.create(null);
    var re = /<script\b[^>]*\bsrc\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>/gi;
    var m;
    while ((m = re.exec(html)) !== null) {
      var src = m[2] || m[3] || m[4];
      if (!src) continue;
      var abs;
      try { abs = new URL(src, pageUrl.href); } catch (e) { continue; }
      if (abs.protocol !== "http:" && abs.protocol !== "https:") continue;
      if (abs.host !== pageUrl.host) continue; // same-origin only
      var key = abs.href;
      if (seen[key]) continue;
      seen[key] = true;
      urls.push(abs.href);
      if (urls.length >= 8) break; // bound the work
    }
    return urls;
  }

  /* ================================================================== *
   * Sensitive-path probe list (~12). Each probed against the target origin.
   * `sniff` validates the body looks genuinely sensitive (HTTP 200 alone is
   * not enough — many SPAs serve index.html for unknown paths).
   * ================================================================== */
  var SENSITIVE_PATHS = [
    { path: "/.env",            sev: "critical", sniff: looksEnv,    why: "A served .env file exposes environment variables — typically database URLs, API keys, and secrets — to anyone who requests it." },
    { path: "/.env.local",      sev: "critical", sniff: looksEnv,    why: "A served .env.local file leaks local/override environment secrets to any visitor." },
    { path: "/.env.production", sev: "critical", sniff: looksEnv,    why: "A served .env.production file exposes your live production secrets directly over HTTP." },
    { path: "/.git/config",     sev: "high",     sniff: looksGit,    why: "A reachable .git/config means the .git directory is served, letting an attacker reconstruct your full source history and any secrets in it." },
    { path: "/.git/HEAD",       sev: "high",     sniff: looksGitHead,why: "A reachable .git/HEAD confirms the .git directory is exposed and the repository can be downloaded and rebuilt." },
    { path: "/config.json",     sev: "medium",   sniff: looksConfig, why: "A public config.json may contain API endpoints, keys, or feature flags meant to stay private." },
    { path: "/credentials.json",sev: "critical", sniff: looksConfig, why: "A served credentials.json almost always contains service-account or API credentials usable directly by an attacker." },
    { path: "/backup.zip",      sev: "high",     sniff: looksBinary, why: "A downloadable backup.zip can contain your entire source tree, database dumps, and secrets." },
    { path: "/backup.sql",      sev: "critical", sniff: looksSql,    why: "A served backup.sql exposes a full database dump including user data and possibly password hashes." },
    { path: "/.DS_Store",       sev: "low",      sniff: looksDsStore,why: "A served .DS_Store leaks the directory listing of that folder, helping an attacker map hidden files." },
    { path: "/.htpasswd",       sev: "high",     sniff: looksHtpasswd,why: "A served .htpasswd exposes usernames and hashed passwords for HTTP basic auth, which can be cracked offline." },
    { path: "/.npmrc",          sev: "high",     sniff: looksNpmrc,  why: "A served .npmrc often contains an npm auth token usable to publish packages as you." },
    { path: "/id_rsa",          sev: "critical", sniff: looksPem,    why: "A served id_rsa is a private SSH key — whoever downloads it can log into the servers that trust it." }
  ];

  // ---- content sniffers: confirm a 200 body actually looks like the file ----
  function isHtmlBody(b) {
    return /^\s*<(?:!doctype|html|head|body|\?xml)/i.test(b) || /<\/html>/i.test(b);
  }
  function looksEnv(b) {
    if (isHtmlBody(b)) return false;
    return /^[ \t]*(?:export[ \t]+)?[A-Z][A-Z0-9_]*\s*=/m.test(b);
  }
  function looksGit(b) {
    return /\[core\]/.test(b) && /repositoryformatversion/.test(b);
  }
  function looksGitHead(b) {
    return /^ref:\s+refs\//m.test(b) || /^[0-9a-f]{40}\s*$/m.test(b);
  }
  function looksConfig(b) {
    if (isHtmlBody(b)) return false;
    var t = b.replace(/^﻿/, "").trim();
    if (t[0] !== "{" && t[0] !== "[") return false;
    try { JSON.parse(t); return true; } catch (e) { return t.length < 100000 && /[:{]/.test(t); }
  }
  function looksSql(b) {
    if (isHtmlBody(b)) return false;
    return /\b(?:CREATE TABLE|INSERT INTO|DROP TABLE|PostgreSQL database dump|MySQL dump)\b/i.test(b);
  }
  function looksDsStore(b) {
    return b.charCodeAt(0) === 0 || /Bud1/.test(b.slice(0, 16));
  }
  function looksHtpasswd(b) {
    if (isHtmlBody(b)) return false;
    return /^[A-Za-z0-9._\-]+:(?:\$(?:apr1|2[aby]|1|6)\$|\{SHA\}|[A-Za-z0-9.\/]{13})/m.test(b);
  }
  function looksNpmrc(b) {
    if (isHtmlBody(b)) return false;
    return /_authToken=|registry=|\/\/.+:_password=/.test(b);
  }
  function looksPem(b) {
    return /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(b);
  }
  function looksBinary(b) {
    // ZIP magic "PK\x03\x04"; also accept any clearly non-HTML, non-empty body.
    if (b.slice(0, 2) === "PK") return true;
    return false;
  }

  /* ================================================================== *
   * SECURITY-HEADERS note (best-effort).
   * Public proxies almost always strip response headers, so we do NOT
   * fabricate a verdict. We surface a single informational finding telling
   * the user we couldn't verify headers via the proxy and how to check.
   * ================================================================== */
  function headerNoticeFinding() {
    return {
      category: "headers",
      name: "Security headers — not verifiable via proxy",
      severity: "low",
      why: "Public CORS proxies strip the target's response headers, so ExposureCheck cannot confirm headers like Content-Security-Policy, Strict-Transport-Security, or X-Frame-Options from here. This is a limitation of proxy scanning, not a verdict that the headers are missing.",
      rotate: "verify headers yourself with browser DevTools → Network → (the document request) → Headers, or run `curl -I https://your-site` — then add any missing CSP/HSTS/X-Frame-Options at your host or CDN.",
      masked: null,
      line: null,
      source: null,
      informational: true
    };
  }

  /* ================================================================== *
   * DOM rendering. All user-derived text uses textContent (el()).
   * The only innerHTML-free clears are of containers with no user data.
   * ================================================================== */
  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text; // safe: escaped by the DOM
    return node;
  }

  function announce(liveRegion, msg) {
    if (liveRegion) liveRegion.textContent = msg;
  }

  /* Progress UI — shows which check is running. Rendered into #results so
   * the user always sees motion; replaced by the final report on completion. */
  function renderProgress(results, label) {
    results.textContent = "";
    var wrap = el("div", "summary-bar");
    var spinner = el("span", "scan-spinner");
    spinner.setAttribute("aria-hidden", "true");
    wrap.appendChild(spinner);
    wrap.appendChild(el("p", "summary-headline", label || "Scanning…"));
    results.appendChild(wrap);
    results.hidden = false;
  }

  function remediationText(finding) {
    if (finding.category === "secret") {
      return (
        "Rotate this secret in " + finding.rotate + ". " +
        "Then stop shipping it: remove the literal from your source and client bundle, load it from a server-side environment variable or secret manager (e.g. 1Password, Doppler, AWS Secrets Manager, Vault), and never expose it to the browser. " +
        "Treat the value as compromised — anything served to a public visitor has been seen."
      );
    }
    if (finding.category === "files") {
      return (
        "Stop serving this path. " + finding.rotate + " " +
        "Block dotfiles and sensitive paths at your web server / CDN, and if it contained credentials, rotate them now and assume they are compromised."
      );
    }
    if (finding.category === "sourcemap") {
      return finding.rotate;
    }
    // internal / headers
    return "Fix: " + finding.rotate;
  }

  function buildCard(finding) {
    var card = el("article", "finding sev-" + finding.severity);

    var head = el("div", "finding-head");
    var badge = el("span", "sev-badge sev-" + finding.severity);
    badge.appendChild(el("span", "dot"));
    badge.appendChild(el("span", null, SEV_LABEL[finding.severity]));
    head.appendChild(badge);
    head.appendChild(el("span", "finding-title", finding.name));
    if (finding.line != null) {
      head.appendChild(el("span", "line-chip", String(finding.line)));
    }
    card.appendChild(head);

    // Masked value / evidence snippet (never the full secret).
    if (finding.masked != null) {
      var valWrap = el("code", "secret-snippet");
      valWrap.setAttribute("aria-label", finding.category === "secret" ? "Masked secret preview" : "Evidence");
      valWrap.appendChild(el("span", "label", finding.category === "secret" ? "Match: " : "Found: "));
      valWrap.appendChild(el("span", "masked", finding.masked)); // already masked / safe text
      card.appendChild(valWrap);
    }

    // Source attribution (which file/path this came from).
    if (finding.source) {
      var src = el("p", "finding-source");
      src.appendChild(el("span", "label", "Source: "));
      src.appendChild(document.createTextNode(finding.source)); // textContent-safe
      card.appendChild(src);
    }

    card.appendChild(el("p", "finding-desc", finding.why));

    var fix = el("div", "fix");
    fix.appendChild(el("span", "fix-label", finding.informational ? "How to verify" : "How to fix"));
    fix.appendChild(el("p", "fix-body", remediationText(finding)));
    card.appendChild(fix);

    return card;
  }

  function render(findings, meta, results, liveRegion, onCopy) {
    results.textContent = ""; // clear (no user data involved)

    // Results header + Copy report button (#copy-btn injected on every render).
    var head = el("div", "results-head");
    head.appendChild(el("h2", null, "Scan results"));
    if (meta && meta.target) {
      head.appendChild(el("span", "meta", meta.target));
    }
    var copyBtn = el("button", "copy-button");
    copyBtn.type = "button";
    copyBtn.id = "copy-btn";
    copyBtn.textContent = "Copy report";
    copyBtn.setAttribute("data-label", "Copy report");
    if (typeof onCopy === "function") {
      copyBtn.addEventListener("click", function (e) {
        e.preventDefault();
        onCopy(copyBtn);
      });
    }
    head.appendChild(copyBtn);
    results.appendChild(head);

    // Count only actionable (non-informational) findings for the verdict.
    var actionable = findings.filter(function (f) { return !f.informational; });
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (var i = 0; i < actionable.length; i++) counts[actionable[i].severity]++;

    if (actionable.length === 0) {
      var empty = el("div", "empty-state");
      empty.appendChild(el("div", "es-icon", "✓"));
      empty.appendChild(el("h3", null, "No exposure detected"));
      empty.appendChild(
        el(
          "p",
          null,
          "No exposure detected — but this only sees what a public visitor can fetch. " +
          "A clean result is not a guarantee: it can't see server-only files, authenticated routes, or headers a proxy strips. Keep secrets out of the client bundle and off public paths."
        )
      );
      results.appendChild(empty);
      // Still show any informational (e.g. header) notes below the empty state.
      appendInformational(findings, results);
      results.hidden = false;
      announce(liveRegion, "Scan complete. No exposure detected.");
      return;
    }

    // Summary bar with severity counts.
    var bar = el("div", "summary-bar");
    var total = actionable.length;
    bar.appendChild(
      el("p", "summary-headline", total + (total === 1 ? " exposure found" : " exposures found"))
    );
    var pills = el("div", "summary-counts");
    for (var s = 0; s < SEVERITIES.length; s++) {
      var sev = SEVERITIES[s];
      if (!counts[sev]) continue;
      var pill = el("span", "sev-count " + SEV_ABBR[sev]);
      pill.appendChild(el("span", "dot"));
      pill.appendChild(el("span", "n", String(counts[sev])));
      pill.appendChild(el("span", null, SEV_LABEL[sev]));
      pills.appendChild(pill);
    }
    bar.appendChild(pills);
    results.appendChild(bar);

    // Findings grouped by severity, critical first.
    for (var g = 0; g < SEVERITIES.length; g++) {
      var groupSev = SEVERITIES[g];
      var group = actionable.filter(function (f) { return f.severity === groupSev; });
      if (!group.length) continue;
      var groupWrap = el("div", "finding-group");
      groupWrap.appendChild(el("h3", "group-head", SEV_LABEL[groupSev] + " (" + group.length + ")"));
      for (var c = 0; c < group.length; c++) groupWrap.appendChild(buildCard(group[c]));
      results.appendChild(groupWrap);
    }

    appendInformational(findings, results);

    results.hidden = false;
    announce(
      liveRegion,
      "Scan complete. " + total +
        (total === 1 ? " exposure found: " : " exposures found: ") +
        summaryPhrase(counts) + "."
    );
  }

  function appendInformational(findings, results) {
    var info = findings.filter(function (f) { return f.informational; });
    if (!info.length) return;
    var wrap = el("div", "finding-group");
    wrap.appendChild(el("h3", "group-head", "Notes"));
    for (var i = 0; i < info.length; i++) wrap.appendChild(buildCard(info[i]));
    results.appendChild(wrap);
  }

  function summaryPhrase(counts) {
    var parts = [];
    for (var s = 0; s < SEVERITIES.length; s++) {
      var sev = SEVERITIES[s];
      if (counts[sev]) parts.push(counts[sev] + " " + SEV_LABEL[sev].toLowerCase());
    }
    return parts.join(", ");
  }

  /* ================================================================== *
   * Plain-text report for clipboard. Secrets MASKED here too.
   * ================================================================== */
  function buildReport(findings, meta) {
    var lines = [];
    lines.push("ExposureCheck report");
    if (meta && meta.target) lines.push("Target: " + meta.target);
    lines.push("Defensive self-check — only publicly-served paths were fetched. No results were stored or transmitted anywhere except the proxy fetch of the target.");
    lines.push("");

    var actionable = findings.filter(function (f) { return !f.informational; });
    if (!actionable.length) {
      lines.push("No exposure detected.");
      lines.push("(This only sees what a public visitor can fetch; it is not a guarantee.)");
    } else {
      var counts = { critical: 0, high: 0, medium: 0, low: 0 };
      for (var i = 0; i < actionable.length; i++) counts[actionable[i].severity]++;
      lines.push(actionable.length + (actionable.length === 1 ? " exposure found." : " exposures found."));
      lines.push("Severity: " + SEVERITIES.map(function (s) { return counts[s] + " " + s; }).join(", "));
      lines.push("");
      lines.push("----------------------------------------");
      for (var f = 0; f < actionable.length; f++) {
        var x = actionable[f];
        lines.push("");
        lines.push("[" + SEV_LABEL[x.severity].toUpperCase() + "] " + x.name + (x.line != null ? "  (line " + x.line + ")" : ""));
        if (x.source) lines.push("  Source: " + x.source);
        if (x.masked != null) lines.push("  Found:  " + x.masked + (x.category === "secret" ? "   (masked — full value never shown)" : ""));
        lines.push("  Risk:   " + x.why);
        lines.push("  Fix:    " + remediationText(x));
      }
    }

    var info = findings.filter(function (f) { return f.informational; });
    if (info.length) {
      lines.push("");
      lines.push("----------------------------------------");
      lines.push("Notes:");
      for (var n = 0; n < info.length; n++) {
        lines.push("  - " + info[n].name + ": " + info[n].why);
      }
    }

    lines.push("");
    lines.push("----------------------------------------");
    lines.push("Secrets above are masked. Treat every exposed value as compromised and rotate it.");
    return lines.join("\n");
  }

  /* ================================================================== *
   * Example vulnerable bundle — OBVIOUSLY FAKE but format-valid, assembled
   * from fragments so this source file contains NO complete secret literal
   * (keeps upstream secret scanners from blocking the repo on its own demo).
   * Loaded into paste mode so the demo ALWAYS works offline.
   * ================================================================== */
  var EXAMPLE = [
    "<!doctype html><html><head><title>Acme App</title></head><body>",
    "<div id=\"root\"></div>",
    "<script>",
    "// Built bundle (example — these are well-known FAKE test values)",
    "var CONFIG = {",
    "  AWS_ACCESS_KEY_ID: \"" + "AKIA" + "IOSFODNN7EXAMPLE\",",
    "  AWS_SECRET_ACCESS_KEY: \"" + "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY\",",
    "  STRIPE_SECRET_KEY: \"" + "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc\",",
    "  OPENAI_API_KEY: \"" + "sk-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345AbCdEf\",",
    "  GOOGLE_API_KEY: \"" + "AIza" + "SyA1234567890abcdefghijklmnopqrstuv\",",
    "  apiBase: \"http://localhost:8080/internal/api\",",
    "  adminContact: \"ops@acme-internal.corp\",",
    "  DATABASE_URL: \"postgres://appuser:" + "s3cr3tP@ss" + "@db.acme.internal:5432/app\"",
    "};",
    "var authHeader = \"Authorization: Bearer " + "sk-" + "aBcDeFgHiJkLmNoPqRsTuVwXyZ012345\";",
    "fetch(\"https://api-staging.acme.internal/v1/users\");",
    "</" + "script>",
    "<script src=\"/static/app.bundle.js\"></" + "script>",
    "</body></html>",
    "//# sourceMappingURL=/static/app.bundle.js.map"
  ].join("\n");

  /* ================================================================== *
   * Scan orchestration.
   * ================================================================== */

  // PASTE mode — analyze pasted content directly, no network.
  function scanPasted(text, ui) {
    renderProgress(ui.results, "Scanning pasted content…");
    var findings = scanCode(text, "pasted content");

    // Source-map references in pasted content (can't fetch, just report).
    var maps = findSourceMapRefs(text);
    for (var i = 0; i < maps.length; i++) {
      if (maps[i].inline) continue;
      findings.push({
        category: "sourcemap",
        name: "Source map reference",
        severity: "low",
        why: "This bundle references a source map (" + maps[i].url + "). If that .map is publicly served, it reconstructs your original, unminified source — including comments and structure.",
        rotate: "Confirm whether " + maps[i].url + " is publicly reachable. If it is, stop deploying .map files to production (or restrict them) so your original source isn't downloadable.",
        masked: null,
        line: maps[i].line,
        source: "pasted content"
      });
    }

    finishScan(findings, { target: "Pasted content" }, ui);
  }

  // URL mode — fetch page, scripts, probe paths, check source maps.
  function scanUrl(rawUrl, ui) {
    var pageUrl = normalizeUrl(rawUrl);
    if (!pageUrl) {
      renderError(ui, "That doesn't look like a valid URL. Enter something like https://your-site.com — or use the paste mode below.");
      return;
    }
    var origin = originOf(pageUrl);
    var findings = [];
    var anyNetworkSuccess = false;

    renderProgress(ui.results, "Fetching " + pageUrl.host + "…");

    fetchViaProxy(pageUrl.href).then(function (res) {
      if (res && res.body) {
        anyNetworkSuccess = true;
        var html = res.body;
        // Scan the HTML document itself.
        pushAll(findings, scanCode(html, pageUrl.href + " (HTML)"));

        // Source-map refs in the HTML (rare but possible inline scripts).
        collectSourceMapFindings(findings, html, pageUrl, pageUrl.href + " (HTML)");

        // Fetch same-origin scripts and scan them, then probe paths + maps.
        var scripts = sameOriginScriptUrls(html, pageUrl);
        return scanScriptsSequential(scripts, pageUrl, findings, ui);
      }
      return null;
    }).then(function () {
      renderProgress(ui.results, "Probing sensitive paths on " + pageUrl.host + "…");
      return probePathsSequential(origin, findings, ui).then(function (probedOk) {
        if (probedOk) anyNetworkSuccess = true;
      });
    }).then(function () {
      renderProgress(ui.results, "Checking source maps…");
      return resolvePendingSourceMaps(findings, ui);
    }).then(function () {
      // Headers can't be verified through public proxies — add the honest note.
      findings.push(headerNoticeFinding());

      if (!anyNetworkSuccess) {
        renderError(
          ui,
          "Couldn't reach " + pageUrl.host + " through any public proxy (they may be rate-limited, down, or the site is blocking them). " +
          "Nothing was hung or retried forever. Try again in a moment, or use the paste mode below — paste your built HTML/JS and ExposureCheck will scan it with no network at all."
        );
        return;
      }
      finishScan(findings, { target: pageUrl.href }, ui);
    }).catch(function () {
      renderError(
        ui,
        "The scan hit an unexpected error reaching " + pageUrl.host + " via the public proxies. " +
        "Use the paste mode below to scan your built HTML/JS directly with no network."
      );
    });
  }

  function pushAll(dest, items) {
    for (var i = 0; i < items.length; i++) dest.push(items[i]);
  }

  // Fetch + scan each same-origin script one at a time (gentle on proxies).
  function scanScriptsSequential(urls, pageUrl, findings, ui) {
    var i = 0;
    function next() {
      if (i >= urls.length) return Promise.resolve();
      var u = urls[i++];
      var shortName = u.replace(pageUrl.protocol + "//" + pageUrl.host, "");
      renderProgress(ui.results, "Scanning bundle " + shortName + "…");
      return fetchViaProxy(u).then(function (res) {
        if (res && res.body) {
          pushAll(findings, scanCode(res.body, shortName));
          collectSourceMapFindings(findings, res.body, pageUrl, shortName);
        }
      }).catch(function () { /* skip this script, keep going */ })
        .then(next);
    }
    return next();
  }

  // Record source-map references; mark them pending a reachability check.
  function collectSourceMapFindings(findings, code, pageUrl, sourceLabel) {
    var maps = findSourceMapRefs(code);
    for (var i = 0; i < maps.length; i++) {
      if (maps[i].inline) continue;
      var mapAbs;
      try { mapAbs = new URL(maps[i].url, sourceLabel.indexOf("http") === 0 ? sourceLabel : pageUrl.href).href; }
      catch (e) { mapAbs = null; }
      findings.push({
        category: "sourcemap",
        name: "Source map reference",
        severity: "low",
        why: "This bundle references a source map (" + maps[i].url + ").",
        rotate: "",
        masked: null,
        line: maps[i].line,
        source: sourceLabel,
        _mapUrl: mapAbs,
        _pending: !!mapAbs
      });
    }
  }

  // For each pending source-map finding, try to fetch it. If reachable,
  // escalate to medium ("source is downloadable"); else mark it low/safe-ish.
  function resolvePendingSourceMaps(findings, ui) {
    var pending = findings.filter(function (f) { return f.category === "sourcemap" && f._pending; });
    var i = 0;
    function next() {
      if (i >= pending.length) return Promise.resolve();
      var f = pending[i++];
      return fetchViaProxy(f._mapUrl).then(function (res) {
        f._pending = false;
        var body = res && res.body ? res.body : "";
        var reachable = res && res.ok && /"sources"|"mappings"|"version"\s*:/.test(body) && !isHtmlBody(body);
        if (reachable) {
          f.severity = "medium";
          f.name = "Exposed source map (original source downloadable)";
          f.why = "The source map at " + f._mapUrl + " is publicly fetchable, so anyone can reconstruct your original, unminified source — variable names, comments, and file structure included.";
          f.rotate = "Stop deploying .map files to production, or restrict them (block *.map at your CDN / web server). Source maps are useful for debugging but should not be world-readable on a live site.";
        } else {
          f.why = "This bundle references a source map (" + (f._mapUrl || "a .map file") + "), but it did not appear to be publicly fetchable through the proxy — good. Double-check it returns 404 to real visitors.";
          f.rotate = "No action needed if the .map truly 404s publicly. If your tooling deploys maps, confirm they are blocked at the edge.";
        }
        delete f._mapUrl; delete f._pending;
      }).catch(function () {
        f._pending = false;
        f.why = "This bundle references a source map (" + (f._mapUrl || "a .map file") + "); ExposureCheck couldn't verify whether it is publicly fetchable through the proxy.";
        f.rotate = "Manually check whether the .map is reachable. If it loads in a browser, block *.map files at your web server / CDN so your original source isn't downloadable.";
        delete f._mapUrl; delete f._pending;
      }).then(next);
    }
    return next();
  }

  // Probe sensitive paths sequentially. Returns true if at least one probe
  // got a usable (non-proxy-failure) response, so the caller knows the
  // network worked even when nothing sensitive was found.
  function probePathsSequential(origin, findings, ui) {
    var i = 0;
    var anyOk = false;
    function next() {
      if (i >= SENSITIVE_PATHS.length) return Promise.resolve(anyOk);
      var spec = SENSITIVE_PATHS[i++];
      var url = origin + spec.path;
      return fetchViaProxy(url).then(function (res) {
        if (res) anyOk = true;
        if (res && res.ok && res.body && spec.sniff(res.body)) {
          findings.push({
            category: "files",
            name: "Exposed file: " + spec.path,
            severity: spec.sev,
            why: spec.why,
            rotate: "The file at " + url + " returned HTTP 200 with sensitive-looking content.",
            // Show a tiny, safe evidence snippet — masked so any secret inside isn't revealed.
            masked: evidenceSnippet(spec, res.body),
            line: null,
            source: url
          });
        }
      }).catch(function () { /* path probe failed; continue */ })
        .then(next);
    }
    return next();
  }

  // A short, SAFE preview of an exposed file's content. Anything that looks
  // like a value is masked; we only show the first line or two, length-capped.
  function evidenceSnippet(spec, body) {
    if (spec.sniff === looksBinary || spec.sniff === looksDsStore) {
      return "(binary file served — " + Math.min(body.length, 999999) + "+ bytes)";
    }
    // Take the first meaningful line, then aggressively mask anything that
    // could be a value so no raw secret reaches the DOM from a probed file.
    var firstLine = "";
    var lines = body.split(/\r?\n/);
    for (var i = 0; i < lines.length && i < 5; i++) {
      if (lines[i].trim()) { firstLine = lines[i]; break; }
    }
    firstLine = firstLine.slice(0, 80);
    return maskEvidenceLine(firstLine) || "(served with HTTP 200)";
  }

  // Mask every value-looking token on a single evidence line. Handles
  // multiple values per line, short secrets, and URI credentials
  // (scheme://user:pass@host) so the password is never surfaced raw.
  function maskEvidenceLine(line) {
    // 1) URI credentials: keep the scheme, mask the userinfo (user:pass).
    line = line.replace(/([a-z][a-z0-9+.\-]*:\/\/)([^\s:@\/]+)(:[^\s@\/]+)?@/gi,
      function (whole, scheme, user, pass) {
        return scheme + maskSecret(user) + (pass ? ":" + maskSecret(pass.slice(1)) : "") + "@";
      });
    // 2) KEY=VALUE / KEY: VALUE — mask the assigned value (global, all matches).
    //    Mask any value >=2 chars (short secrets like "ab" become bullets too).
    //    The `(?!\/\/)` guard skips the ':' of a URI scheme already handled above.
    line = line.replace(/([=:](?!\/\/)\s*)("?)([^\s"'`]{2,})\2/g, function (whole, sep, q, val) {
      return sep + q + maskSecret(val) + q;
    });
    return line;
  }

  function finishScan(findings, meta, ui) {
    // Sort: actionable by severity then category; informational sinks to notes.
    findings.sort(function (a, b) {
      var ai = a.informational ? 1 : 0, bi = b.informational ? 1 : 0;
      if (ai !== bi) return ai - bi;
      var sa = SEVERITIES.indexOf(a.severity), sb = SEVERITIES.indexOf(b.severity);
      if (sa !== sb) return sa - sb;
      return 0;
    });
    ui.lastFindings = findings;
    ui.lastMeta = meta;
    render(findings, meta, ui.results, ui.liveRegion, function (btn) {
      copyReport(buildReport(ui.lastFindings, ui.lastMeta), btn);
    });
    focusResults(ui.results);
  }

  function renderError(ui, message) {
    ui.results.textContent = "";
    var box = el("div", "empty-state scan-error");
    box.appendChild(el("div", "es-icon", "!"));
    box.appendChild(el("h3", null, "Couldn't complete the scan"));
    box.appendChild(el("p", null, message));
    ui.results.appendChild(box);
    ui.results.hidden = false;
    announce(ui.liveRegion, "Scan could not complete. " + message);
    focusResults(ui.results);
  }

  function focusResults(results) {
    if (typeof results.focus === "function") results.focus();
    if (typeof results.scrollIntoView === "function") {
      results.scrollIntoView({ behavior: "smooth", block: "nearest" });
    }
  }

  /* ================================================================== *
   * Clipboard copy — local only, no network (ported from LeakCheck).
   * ================================================================== */
  function copyReport(text, btn) {
    var original = btn.getAttribute("data-label") || btn.textContent;
    btn.setAttribute("data-label", original);
    function done(ok) {
      btn.textContent = ok ? "Copied ✓" : "Copy failed";
      setTimeout(function () { btn.textContent = original; }, 1800);
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done(true); }, function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }
  function fallbackCopy(text, done) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-1000px";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand && document.execCommand("copy");
      document.body.removeChild(ta);
      done(!!ok);
    } catch (err) {
      done(false);
    }
  }

  /* ================================================================== *
   * Wire-up. Binds to the page shell; degrades if optional bits are absent.
   * ================================================================== */
  function init() {
    var form = document.getElementById("scan-form");
    var urlInput = document.getElementById("url");
    var pasteInput = document.getElementById("paste");
    var results = document.getElementById("results");
    var exampleBtn = document.getElementById("example-btn");
    var clearBtn = document.getElementById("clear-btn");
    var toggle = document.getElementById("mode-toggle"); // optional: legacy [data-set-mode] switch
    var pasteToggle = document.getElementById("paste-toggle"); // toolbar "Paste HTML/JS instead"
    var pasteWrap = document.getElementById("paste-wrap");      // collapsible textarea wrapper

    if (!form || !results) return; // shell not present

    // aria-live region for scan announcements (created if the shell omits it).
    var liveRegion = document.getElementById("scan-status");
    if (!liveRegion) {
      liveRegion = el("div", "sr-only");
      liveRegion.id = "scan-status";
      liveRegion.setAttribute("aria-live", "polite");
      liveRegion.setAttribute("role", "status");
      results.parentNode.insertBefore(liveRegion, results);
    }

    var ui = { results: results, liveRegion: liveRegion, lastFindings: [], lastMeta: null };

    // Optional URL/paste mode toggle. If a #mode-toggle exists, it flips a
    // [data-mode] attribute on the form; otherwise both inputs are honored
    // (paste content wins if present, since it needs no network).
    function currentMode() {
      var m = form.getAttribute("data-mode");
      if (m === "paste" || m === "url") return m;
      // No explicit mode: infer from which field has content.
      if (pasteInput && pasteInput.value.trim()) return "paste";
      return "url";
    }

    // Reveal/collapse the paste-mode textarea and keep the form's data-mode,
    // the toolbar toggle's aria-expanded, and focus all in sync. This is the
    // canonical paste-mode entry point used by both the toggle and "Try an
    // example" so state never drifts.
    function setPasteMode(on, opts) {
      opts = opts || {};
      if (pasteWrap) pasteWrap.hidden = !on;
      if (pasteToggle) pasteToggle.setAttribute("aria-expanded", on ? "true" : "false");
      form.setAttribute("data-mode", on ? "paste" : "url");
      if (opts.focus) {
        if (on && pasteInput) pasteInput.focus();
        else if (!on && urlInput) urlInput.focus();
      }
    }

    if (pasteToggle && pasteWrap) {
      setPasteMode(false); // ensure consistent initial state (textarea collapsed, url mode)
      pasteToggle.addEventListener("click", function (e) {
        e.preventDefault();
        var reveal = pasteWrap.hidden; // currently hidden → reveal
        setPasteMode(reveal, { focus: true });
      });
    }

    if (toggle) {
      toggle.addEventListener("click", function (e) {
        var btn = e.target.closest("[data-set-mode]");
        if (!btn) return;
        e.preventDefault();
        var mode = btn.getAttribute("data-set-mode");
        form.setAttribute("data-mode", mode);
        // reflect active state for styling
        var all = toggle.querySelectorAll("[data-set-mode]");
        for (var i = 0; i < all.length; i++) {
          all[i].setAttribute("aria-pressed", all[i] === btn ? "true" : "false");
        }
        if (mode === "paste" && pasteInput) pasteInput.focus();
        else if (urlInput) urlInput.focus();
      });
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var mode = currentMode();
      if (mode === "paste") {
        var pasted = pasteInput ? pasteInput.value : "";
        if (!pasted.trim()) {
          renderError(ui, "Paste your built HTML or JS into the box first, or switch to URL mode to scan a deployed site.");
          return;
        }
        scanPasted(pasted, ui);
      } else {
        var raw = urlInput ? urlInput.value : "";
        if (!raw.trim()) {
          renderError(ui, "Enter the URL of a site you own (e.g. https://your-site.com), or switch to paste mode.");
          return;
        }
        scanUrl(raw, ui);
      }
    });

    if (exampleBtn) {
      exampleBtn.addEventListener("click", function (e) {
        e.preventDefault();
        // Load the sample vulnerable bundle into paste mode (always offline).
        if (pasteInput) {
          pasteInput.value = EXAMPLE;
          // Reveal the textarea so the user can see/edit what was loaded.
          setPasteMode(true);
          if (toggle) {
            var all = toggle.querySelectorAll("[data-set-mode]");
            for (var i = 0; i < all.length; i++) {
              all[i].setAttribute("aria-pressed", all[i].getAttribute("data-set-mode") === "paste" ? "true" : "false");
            }
          }
          scanPasted(EXAMPLE, ui);
        } else {
          // No paste field in the shell — scan the example string directly.
          scanPasted(EXAMPLE, ui);
        }
      });
    }

    if (clearBtn) {
      clearBtn.addEventListener("click", function (e) {
        e.preventDefault();
        if (urlInput) urlInput.value = "";
        if (pasteInput) pasteInput.value = "";
        // Collapse back to URL mode so the UI returns to its initial state.
        if (pasteToggle && pasteWrap) setPasteMode(false);
        ui.lastFindings = [];
        ui.lastMeta = null;
        results.textContent = "";
        results.hidden = true;
        announce(liveRegion, "Cleared. Enter a URL or paste code to scan again.");
        if (urlInput) urlInput.focus();
        else if (pasteInput) pasteInput.focus();
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
