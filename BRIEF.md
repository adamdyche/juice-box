# JuiceBox — Day 1 Brief

Welcome! JuiceBox is a small online store that is **deliberately full of security holes**. Your job is to find them, prove them, and write them up — the same loop you'd run on a real engagement, in a safe sandbox.

## Rules of engagement

- **Scope:** the JuiceBox app at `http://localhost:3000` only. Nothing else on the machine or network.
- **This is your own local copy.** Break it freely — `npm run seed` resets the data anytime.
- **Document as you go.** A vuln you can't reproduce or explain doesn't count. Use `FINDINGS_TEMPLATE.md`.
- **No need to attack the host OS, your shell, or other apps.** If an exploit *can* run system commands, note it and stop — don't go wandering.
- **Ask questions.** Getting stuck and talking it through is the point, not a failure.

## Setup checklist (do this first)

- [ ] `node --version` is 18 or higher
- [ ] `npm install` then `npm start`, and `http://localhost:3000` loads
- [ ] An intercepting proxy installed and working: **Burp Suite Community** or **OWASP ZAP**
- [ ] Browser traffic routed through the proxy (FoxyProxy or the browser's built-in proxy) and HTTPS/CA cert set up
- [ ] You can see a request in the proxy, **modify it, and replay it** (Burp Repeater / ZAP Manual Request)
- [ ] Browser DevTools open: Network, Console, and Application (cookies/storage) tabs

> If you only do one setup thing well, make it the **proxy**. A lot of what's interesting here happens in the request, not the page.

## How to work

1. **Map the app first (10–15 min).** Click through every page. Register an account, add to cart, check out, leave a review, open the chatbot, view your account/orders. Watch the requests in your proxy as you go. Note every parameter, endpoint, and cookie.
2. **Pick an area and probe it.** For each input ask: *what does the server do with this?* Try the obvious bad input (a quote, a script tag, a number that should be positive, an id that isn't yours).
3. **When something looks off, confirm it** with a clean, minimal proof of concept (one request / one payload).
4. **Write it up immediately** in your findings doc while it's fresh.
5. **Move on — but don't assume one bug per feature.** Several areas hide more than one issue, at different difficulty levels.

## The scoreboard

There's a **self-check scoreboard at `http://localhost:3000/scoreboard`**. It lists every challenge and marks each one solved when you actually pull off the exploit (a few ask you to paste in a flag you find). Each has a **Hint** you can expand — try without it first, then use it if you're stuck for more than ~15 minutes.

Treat the scoreboard as a checklist, **not** as the deliverable. The real output is your findings report: clear reproduction steps, impact, and a fix for each issue.

## What "good" looks like by end of day

- A findings doc with several confirmed issues, each with a working PoC and a remediation.
- At least one issue you found **without** the hint.
- Honest severity ratings you can defend.
- A couple of questions or "I wasn't sure about X" notes — those are great discussion material.

Have fun. Be curious, be methodical, and read the responses carefully. 🔍
