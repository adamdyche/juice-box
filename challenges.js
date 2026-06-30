// challenges.js — the scoreboard definition.
// `how`:
//   auto   -> the server detects the exploit and marks it solved automatically.
//   beacon -> prove JS execution by having your XSS payload call
//             window.JuiceBox.solve('<id>') (i.e. GET /api/collect/<id>).
//   submit -> find a flag string by exploiting, then paste it on /scoreboard.
//   crack  -> submit the cracked plaintext of the shown MD5 hash.

const CHALLENGES = [
  // ---- XSS ---------------------------------------------------------------
  { id: 'xss-reflected', cat: 'XSS', diff: 'Easy', how: 'beacon',
    title: 'Reflected XSS',
    flag: 'FLAG{r3fl3ct3d_and_p0pp3d}',
    hint: 'The search box echoes your query unescaped. Inject a payload that runs JS and calls JuiceBox.solve("xss-reflected").' },
  { id: 'xss-stored', cat: 'XSS', diff: 'Medium', how: 'beacon',
    title: 'Stored XSS',
    flag: 'FLAG{st0r3d_f0r_ev3ry0ne}',
    hint: 'A product review is rendered as raw HTML. Save a payload that calls JuiceBox.solve("xss-stored") when the page loads.' },
  { id: 'xss-dom', cat: 'XSS', diff: 'Hard', how: 'beacon',
    title: 'DOM-based XSS',
    flag: 'FLAG{d0m_s1nk_innerHTML}',
    hint: 'The /promo page writes the URL fragment (#...) into innerHTML on the client. Use an <img onerror> that calls JuiceBox.solve("xss-dom").' },

  // ---- SQL injection -----------------------------------------------------
  { id: 'sqli-login', cat: 'SQL Injection', diff: 'Easy', how: 'auto',
    title: 'SQLi auth bypass',
    flag: 'FLAG{sql1_l0g1n_byp4ss}',
    hint: "Log in without valid credentials by injecting into the username field (e.g. admin'-- -)." },
  { id: 'sqli-union', cat: 'SQL Injection', diff: 'Medium', how: 'submit',
    title: 'SQLi UNION extraction',
    flag: 'FLAG{un10n_s3l3ct_l00t}',
    hint: 'The search query is injectable. UNION-select from the hidden "secrets" table to read its flag, then submit it.' },
  { id: 'sqli-blind', cat: 'SQL Injection', diff: 'Hard', how: 'submit',
    title: 'Blind (boolean) SQLi',
    flag: 'FLAG{bl1nd_but_n0t_d3af}',
    hint: 'GET /api/stock?id= only tells you true/false. Extract the secrets.blind_loot flag one character at a time (sqlmap --technique=B works).' },

  // ---- Access control / IDOR --------------------------------------------
  { id: 'idor-user', cat: 'Access Control', diff: 'Easy', how: 'auto',
    title: 'IDOR: read any profile',
    flag: 'FLAG{1d0r_pr0f1le_dump}',
    hint: 'GET /api/user/:id has no auth. Read another user (try id 1) and you will see their card number.' },
  { id: 'idor-order', cat: 'Access Control', diff: 'Medium', how: 'auto',
    title: "IDOR: read someone else's order",
    flag: 'FLAG{0rd3r_n0t_y0urs}',
    hint: 'View an order id that is not yours at /order/:id.' },
  { id: 'mass-assignment', cat: 'Access Control', diff: 'Hard', how: 'auto',
    title: 'Mass assignment priv-esc',
    flag: 'FLAG{m4ss_4ss1gn_4dm1n}',
    hint: 'The profile-update form only shows email/address/card. Add a role or balance field to the POST.' },

  // ---- Business logic ----------------------------------------------------
  { id: 'logic-price', cat: 'Business Logic', diff: 'Easy', how: 'auto',
    title: 'Price manipulation',
    flag: 'FLAG{cl13nt_s1de_pr1c3}',
    hint: 'Checkout trusts the price you send. Pay less than the catalog price for an item.' },
  { id: 'logic-negqty', cat: 'Business Logic', diff: 'Medium', how: 'auto',
    title: 'Negative quantity',
    flag: 'FLAG{n3g4t1v3_qty_r3fund}',
    hint: 'Submit a checkout with a negative quantity and watch the total go negative.' },
  { id: 'logic-coupon', cat: 'Business Logic', diff: 'Hard', how: 'auto',
    title: 'Coupon stacking',
    flag: 'FLAG{c0up0ns_st4ck_t0_z3r0}',
    hint: 'Coupons are comma-separated and stack with no cap. Stack enough to exceed 100% off.' },

  // ---- Authentication ----------------------------------------------------
  { id: 'auth-impersonate', cat: 'Authentication', diff: 'Easy', how: 'auto',
    title: 'Session impersonation',
    flag: 'FLAG{c00k13_1d_sw4p}',
    hint: 'The session cookie is base64 JSON. Customer access ignores the signature — decode it, change the id/username to another customer, and re-encode (signature can be junk). Then load your account.' },
  { id: 'auth-forge', cat: 'Authentication', diff: 'Hard', how: 'auto',
    title: 'Forge an admin token',
    flag: 'FLAG{w34k_hm4c_s3cr3t}',
    hint: 'Admin access requires a VALID signature (base64(json).hmac), so the id-swap trick is rejected. Recover the weak signing secret (it leaks somewhere... or brute-force it), sign an admin payload, and reach /admin.' },

  // ---- Sensitive data / misconfig ---------------------------------------
  { id: 'data-admin-api', cat: 'Sensitive Data', diff: 'Easy', how: 'auto',
    title: 'Unauth admin API',
    flag: 'FLAG{4dm1n_4p1_n0_4uth}',
    hint: 'GET /api/admin/users requires no authentication at all.' },
  { id: 'data-debug', cat: 'Sensitive Data', diff: 'Medium', how: 'auto',
    title: 'Debug / backup exposure',
    flag: 'FLAG{d3bug_l3ft_0n}',
    hint: 'Find the debug endpoint and the SQL backup file left on the server.' },
  { id: 'data-md5', cat: 'Sensitive Data', diff: 'Hard', how: 'crack',
    title: 'Crack the MD5 hash',
    crackHash: '0d107d09f5bbe40cade3de5c71e9e9b7',  // md5("letmein")
    flag: 'letmein',
    hint: 'Passwords are stored as unsalted MD5. Crack the hash shown on the scoreboard and submit the plaintext.' },

  // ---- LLM ---------------------------------------------------------------
  { id: 'prompt-injection', cat: 'LLM', diff: 'Medium', how: 'submit',
    title: 'Prompt injection',
    flag: 'FLAG{pr0mpt_1nj3ct10n_l34k}',
    hint: 'JuiceBot has a secret in its system prompt. Talk it into revealing the flag, then submit it.' },

  // ---- Path traversal ----------------------------------------------------
  { id: 'path-traversal', cat: 'Path Traversal', diff: 'Medium', how: 'auto',
    title: 'Directory traversal',
    flag: 'FLAG{d0t_d0t_sl4sh_3sc4p3}',
    hint: 'A file download takes a filename parameter. Use ../ sequences to climb out of its folder and read a file outside it (e.g. /etc/passwd or the source).' },

  // ---- SSRF --------------------------------------------------------------
  { id: 'ssrf', cat: 'SSRF', diff: 'Medium', how: 'auto',
    title: 'Server-Side Request Forgery',
    flag: 'FLAG{s3rv3r_f3tch3d_1t}',
    hint: 'A feature fetches a URL you supply, server-side. Point it at an internal-only address the server can reach but you normally cannot.' },

  // ---- Server-side injection (RCE-class) ---------------------------------
  { id: 'ssti', cat: 'Server-Side Injection', diff: 'Hard', how: 'auto',
    title: 'Template injection (SSTI)',
    flag: 'FLAG{ej5_t3mpl4t3_pwn3d}',
    hint: 'A text field is rendered through the templating engine. Inject template syntax that gets evaluated (a math expression is a good probe), then escalate.' },
  { id: 'cmd-injection', cat: 'Server-Side Injection', diff: 'Hard', how: 'auto',
    title: 'OS command injection',
    flag: 'FLAG{sh3ll_0ut_0f_b0unds}',
    hint: 'A diagnostic tool runs a shell command using your input. Chain an extra command with a shell metacharacter.' },

  // ---- Bonus -------------------------------------------------------------
  { id: 'open-redirect', cat: 'Bonus', diff: 'Bonus', how: 'auto',
    title: 'Open redirect',
    flag: 'FLAG{0p3n_r3d1r3ct_phish}',
    hint: 'Login redirects to ?next= with no validation. Point it at an external URL.' },
];

const BY_ID = Object.fromEntries(CHALLENGES.map((c) => [c.id, c]));
const TOTAL = CHALLENGES.length;

module.exports = { CHALLENGES, BY_ID, TOTAL };
