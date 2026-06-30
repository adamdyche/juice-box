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
    hint: "Some pages put your input straight back into the response. Find one where what you type is reflected without being escaped." },
  { id: 'xss-stored', cat: 'XSS', diff: 'Medium', how: 'beacon',
    title: 'Stored XSS',
    flag: 'FLAG{st0r3d_f0r_ev3ry0ne}',
    hint: "Some input you submit is shown back to other users later. What if it isn't sanitised when it's stored or displayed?" },
  { id: 'xss-dom', cat: 'XSS', diff: 'Hard', how: 'beacon',
    title: 'DOM-based XSS',
    flag: 'FLAG{d0m_s1nk_innerHTML}',
    hint: "Not all XSS involves the server. Watch what the client-side JavaScript does with parts of the URL." },

  // ---- SQL injection -----------------------------------------------------
  { id: 'sqli-login', cat: 'SQL Injection', diff: 'Easy', how: 'auto',
    title: 'SQLi auth bypass',
    flag: 'FLAG{sql1_l0g1n_byp4ss}',
    hint: "Logging in runs a database query built from what you typed. What if that query isn't built safely?" },
  { id: 'sqli-union', cat: 'SQL Injection', diff: 'Medium', how: 'submit',
    title: 'SQLi UNION extraction',
    flag: 'FLAG{un10n_s3l3ct_l00t}',
    hint: "A search talks to the database. Could you make it return rows from a table it was never meant to? A flag is hidden in one of them." },
  { id: 'sqli-blind', cat: 'SQL Injection', diff: 'Hard', how: 'submit',
    title: 'Blind (boolean) SQLi',
    flag: 'FLAG{bl1nd_but_n0t_d3af}',
    hint: "One endpoint only answers true or false — but a yes/no oracle can still leak data one character at a time. There's a flag to recover." },

  // ---- Access control / IDOR --------------------------------------------
  { id: 'idor-user', cat: 'Access Control', diff: 'Easy', how: 'auto',
    title: 'IDOR: read any profile',
    flag: 'FLAG{1d0r_pr0f1le_dump}',
    hint: "Some endpoints return a record by id with no check that it belongs to you. What can you read that you shouldn't?" },
  { id: 'idor-order', cat: 'Access Control', diff: 'Medium', how: 'auto',
    title: "IDOR: read someone else's order",
    flag: 'FLAG{0rd3r_n0t_y0urs}',
    hint: "Identifiers in the URL are sequential. Can you reach another customer's data just by changing one?" },
  { id: 'mass-assignment', cat: 'Access Control', diff: 'Hard', how: 'auto',
    title: 'Mass assignment priv-esc',
    flag: 'FLAG{m4ss_4ss1gn_4dm1n}',
    hint: "When you save your profile, what fields does the server actually accept? Could you send ones the form never offered?" },

  // ---- Business logic ----------------------------------------------------
  { id: 'logic-price', cat: 'Business Logic', diff: 'Easy', how: 'auto',
    title: 'Price manipulation',
    flag: 'FLAG{cl13nt_s1de_pr1c3}',
    hint: "At checkout, where does the price the server charges actually come from? Can you influence it?" },
  { id: 'logic-negqty', cat: 'Business Logic', diff: 'Medium', how: 'auto',
    title: 'Negative quantity',
    flag: 'FLAG{n3g4t1v3_qty_r3fund}',
    hint: "What happens if you submit a value that should never be allowed — like a quantity below zero?" },
  { id: 'logic-coupon', cat: 'Business Logic', diff: 'Hard', how: 'auto',
    title: 'Coupon stacking',
    flag: 'FLAG{c0up0ns_st4ck_t0_z3r0}',
    hint: "Discounts are checked, but is there any limit on how many you can apply at once?" },

  // ---- Authentication ----------------------------------------------------
  { id: 'auth-impersonate', cat: 'Authentication', diff: 'Easy', how: 'auto',
    title: 'Session impersonation',
    flag: 'FLAG{c00k13_1d_sw4p}',
    hint: "Look closely at your session cookie. What's actually stopping you from changing who it says you are?" },
  { id: 'auth-forge', cat: 'Authentication', diff: 'Hard', how: 'auto',
    title: 'Forge an admin token',
    flag: 'FLAG{w34k_hm4c_s3cr3t}',
    hint: "Impersonating a customer is easy; the admin role is protected differently. How strong is that protection, and could the secret behind it leak?" },

  // ---- Sensitive data / misconfig ---------------------------------------
  { id: 'data-admin-api', cat: 'Sensitive Data', diff: 'Easy', how: 'auto',
    title: 'Unauth admin API',
    flag: 'FLAG{4dm1n_4p1_n0_4uth}',
    hint: "Admin actions should require admin access. Do all of the admin endpoints actually check?" },
  { id: 'data-debug', cat: 'Sensitive Data', diff: 'Medium', how: 'auto',
    title: 'Debug / backup exposure',
    flag: 'FLAG{d3bug_l3ft_0n}',
    hint: "Developers leave things behind. Look for endpoints or files that were never meant to be public." },
  { id: 'data-md5', cat: 'Sensitive Data', diff: 'Hard', how: 'crack',
    title: 'Crack the MD5 hash',
    crackHash: '0d107d09f5bbe40cade3de5c71e9e9b7',  // md5("letmein")
    flag: 'letmein',
    hint: "Suppose you've recovered some password hashes (other challenges help with that). How well are they protected? Crack the one shown below and submit the plaintext." },

  // ---- LLM ---------------------------------------------------------------
  { id: 'prompt-injection', cat: 'LLM', diff: 'Medium', how: 'submit',
    title: 'Prompt injection',
    flag: 'FLAG{pr0mpt_1nj3ct10n_l34k}',
    hint: "The chatbot was told to keep a secret. Can you get it to ignore those instructions? There's a flag to recover." },

  // ---- Path traversal ----------------------------------------------------
  { id: 'path-traversal', cat: 'Path Traversal', diff: 'Medium', how: 'auto',
    title: 'Directory traversal',
    flag: 'FLAG{d0t_d0t_sl4sh_3sc4p3}',
    hint: "A download serves a file by name. What if the name points somewhere outside the intended folder?" },

  // ---- SSRF --------------------------------------------------------------
  { id: 'ssrf', cat: 'SSRF', diff: 'Medium', how: 'auto',
    title: 'Server-Side Request Forgery',
    flag: 'FLAG{s3rv3r_f3tch3d_1t}',
    hint: "A feature fetches a URL for you. From whose network position is that request actually made?" },

  // ---- Server-side injection (RCE-class) ---------------------------------
  { id: 'ssti', cat: 'Server-Side Injection', diff: 'Hard', how: 'auto',
    title: 'Template injection (SSTI)',
    flag: 'FLAG{ej5_t3mpl4t3_pwn3d}',
    hint: "A preview feature renders the text you give it. What if your text contains the templating engine's own syntax?" },
  { id: 'cmd-injection', cat: 'Server-Side Injection', diff: 'Hard', how: 'auto',
    title: 'OS command injection',
    flag: 'FLAG{sh3ll_0ut_0f_b0unds}',
    hint: "A diagnostic tool runs a system command built from your input. What if your input is more than just a hostname?" },

  // ---- Bonus -------------------------------------------------------------
  { id: 'open-redirect', cat: 'Bonus', diff: 'Bonus', how: 'auto',
    title: 'Open redirect',
    flag: 'FLAG{0p3n_r3d1r3ct_phish}',
    hint: "After login you're redirected somewhere. Who controls the destination?" },
];

const BY_ID = Object.fromEntries(CHALLENGES.map((c) => [c.id, c]));
const TOTAL = CHALLENGES.length;

module.exports = { CHALLENGES, BY_ID, TOTAL };
