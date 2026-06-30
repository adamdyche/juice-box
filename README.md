# 🧃 JuiceBox — a deliberately vulnerable training store

JuiceBox is a tiny online-store web app (think a miniature [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)) built **on purpose** with security bugs in it. It exists so an intern can practice finding and exploiting common web vulnerabilities in a safe, local environment.

> ⚠️ **This app is intentionally insecure. Run it only on your own machine. Never deploy it, expose it to a network, or put real data in it.**

## Requirements

- **Node.js 18+** (tested on Node 22). Check with `node --version`.
- macOS / Linux / Windows. No database server needed — it uses an embedded SQLite file.
- *(Optional)* [Ollama](https://ollama.com) running locally for the AI chatbot challenge. The app works fine without it (it falls back to a canned assistant).

## Run it

```bash
npm install
npm start
```

Then open **http://localhost:3000**.

To wipe and re-seed the database (fresh users, products, reviews, orders):

```bash
npm run seed
```

The database is a single file, `juicebox.db`, created on first run. Delete it to start over.

### Optional: enable the real AI chatbot

```bash
# in a separate terminal
ollama pull llama3.2
ollama serve        # usually already running on macOS
```

The chatbot at **/chat** will use Ollama automatically if it's reachable at `http://localhost:11434`. Override with env vars:

```bash
OLLAMA_URL=http://localhost:11434 OLLAMA_MODEL=llama3.2 npm start
```

## Accounts

The store has an `admin` account and several customers (`alice`, `bob`, `carol`), plus you can **register your own** account from the site. The seeded users' passwords are intentionally *not* listed here — getting access you shouldn't have is part of the exercise.

## The challenge

This app is planted with vulnerabilities across the **OWASP Top 10**. Your job is to find them. The broad categories in play:

- Injection (SQL, command, template, …)
- Cross-Site Scripting (XSS)
- Broken Access Control / IDOR
- Business-logic flaws
- Authentication & session weaknesses
- Sensitive data exposure & security misconfiguration
- Server-side request forgery (SSRF) and path traversal
- An LLM-specific weakness in the chatbot
- A few smaller bonus issues

Most categories have **more than one bug**, at a range of difficulty — some are obvious in the browser, others only show up if you watch the raw HTTP and poke at endpoints directly. Don't stop at the first thing you find in an area.

If you're working through **PortSwigger Web Security Academy**, you'll recognize a lot of these — start with the simplest version of each class and work up.

For each finding, capture: **where** it is, a **proof-of-concept** (request/payload), the **impact**, and a **remediation**.

**Start here:** read **[BRIEF.md](BRIEF.md)** for the rules of engagement, a setup checklist, and how to work. Record what you find using **[FINDINGS_TEMPLATE.md](FINDINGS_TEMPLATE.md)**.

> 💡 Treat the whole site as in-scope: every page, every form, every API endpoint, and every cookie. Use your browser's dev tools and an intercepting proxy (Burp / ZAP / mitmproxy) — much of what's interesting never shows up in the rendered page.

## 🏁 Scoreboard (self-check)

Open **http://localhost:3000/scoreboard** to track your progress. It lists every challenge, shows how many you've solved, and has a per-challenge **Hint** you can expand *if you get stuck* (try without it first).

How challenges get marked solved:
- **Auto** — most are detected automatically the moment you actually pull off the exploit. Just refresh the scoreboard.
- **Submit** — a few hide a `FLAG{...}` string that only appears once you exploit them. Paste it into the submit box.
- **Beacon** — the XSS challenges are solved by getting JavaScript to run in the page and call `JuiceBox.solve('<challenge-id>')` (a helper loaded on every page). That proves real code execution, not just a payload sitting in the source.
- **Crack** — one challenge gives you a hash to crack offline; submit the plaintext.

Progress is saved per-browser (an anonymous cookie), so you get your own board. There's a **Reset my progress** button on the page. Running `npm run seed` clears stored payloads/junk data but **keeps** scoreboard progress.

## Project layout

```
server.js          all routes and app logic
db.js              SQLite schema + seed data
challenges.js      scoreboard challenge registry
views/             EJS templates (pages)
public/            CSS + client-side scripts
```

> Reading the source is fair game (it's how you'd approach a white-box review) — but try to find things by using the app first.

Happy hunting. 🔍
