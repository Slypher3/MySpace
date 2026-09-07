# 🛡️ CyberSpace

> A cyberpunk-themed network reconnaissance & security awareness dashboard — powered by free, keyless APIs.

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗██████╗  █████╗  ██████╗███████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗██████╔╝███████║██║     █████╗
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔═══╝ ██╔══██║██║     ██╔══╝
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║██║     ██║  ██║╚██████╗███████╗
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝
```

A static, single-page site with a dark cyberpunk aesthetic — glassmorphism cards, neon glow effects, scanline overlays, and a boot sequence animation. All data processing happens client-side. **Zero dependencies, zero build tools.**

---

## ✨ Features

### 🌐 Network Recon
- Auto-detects your **public IP**, geolocation, ISP, and ASN via [ipapi.co](https://ipapi.co)
- Queries [Shodan InternetDB](https://internetdb.shodan.io) for **open ports**, exposed hostnames, tags, and **known CVEs**
- Displays results in a data grid + raw terminal output

### 🔑 Password Breach Checker
- Checks passwords against the [Have I Been Pwned](https://haveibeenpwned.com) breach database
- Uses the **k-Anonymity model** — your password **never leaves the browser**
- SHA-1 hash computed locally via `crypto.subtle`, only a 5-character prefix is sent to the API

### 😂 Cyber Jokes
- Fetches programming jokes from [JokeAPI v2](https://v2.jokeapi.dev)
- Supports single-line and two-part (setup → delivery) joke formats
- NSFW content filtered — safe for work terminals

### 📡 About
- Project overview, API documentation links, and tech stack info

---

## 🎨 Design

| Element | Details |
|---------|---------|
| **Theme** | Dark cyberpunk with neon accents |
| **Colors** | Cyan `#00f0ff` · Magenta `#ff00aa` · Neon Green `#00ff41` · Orange `#ff6600` |
| **Fonts** | [Orbitron](https://fonts.google.com/specimen/Orbitron) (headings) + [Share Tech Mono](https://fonts.google.com/specimen/Share+Tech+Mono) (body) |
| **Effects** | Glassmorphism cards, scanline overlay, grid background, neon glow borders, glitch hover, cursor blink |
| **Boot** | Terminal-style boot sequence animation on first load |
| **Responsive** | Mobile-first — tab labels collapse to icons on small screens |

---

## 🚀 Getting Started

No build step, no `npm install`. Just serve the `src/` directory.

```bash
# Clone the repo
git clone https://github.com/Slypher3/MySpace.git
cd MySpace

# Serve locally (Python)
python3 -m http.server 8080 -d src

# Or with Node
npx -y serve src

# Open in browser
open http://localhost:8080
```

---

## 📂 Project Structure

```
src/
├── index.html              # Main page — tabs, boot screen, footer
├── css/
│   └── style.css           # Full design system (650+ lines)
├── js/
│   ├── app.js              # Boot sequence, tab switching, keyboard nav
│   ├── ip-dashboard.js     # ipapi.co + Shodan InternetDB integration
│   ├── pwned.js            # HIBP password checker (k-Anonymity)
│   └── jokes.js            # JokeAPI v2 programming jokes
└── main.py                 # Original starter script (unused)
```

---

## 🔌 APIs Used

All APIs are **free and require no authentication key**.

| API | Endpoint | Purpose |
|-----|----------|---------|
| [ipapi.co](https://ipapi.co) | `https://ipapi.co/json/` | IP geolocation, ISP, ASN |
| [Shodan InternetDB](https://internetdb.shodan.io) | `https://internetdb.shodan.io/{ip}` | Open ports, hostnames, CVEs |
| [HIBP Pwned Passwords](https://haveibeenpwned.com/API/v3#PwnedPasswords) | `https://api.pwnedpasswords.com/range/{hash5}` | Password breach lookup (k-Anonymity) |
| [JokeAPI v2](https://v2.jokeapi.dev) | `https://v2.jokeapi.dev/joke/Programming` | Programming jokes |

---

## 🔒 Privacy

- **No tracking, no analytics, no cookies**
- All password hashing is done **locally in the browser** using the Web Crypto API
- Only the first 5 characters of the SHA-1 hash are ever transmitted
- IP data is fetched directly from the APIs — this site does not store or log anything

---

## 🛠️ Tech Stack

- **HTML5** — Semantic structure with ARIA roles
- **CSS3** — Custom properties, glassmorphism, `backdrop-filter`, CSS animations
- **Vanilla JavaScript** — ES6+, `fetch`, `crypto.subtle`, custom events
- **Zero dependencies** — No frameworks, no build tools, no npm packages

---

## 📄 License

[MIT](LICENSE)

---

<p align="center">
  <sub>Built with ☕ and neon glow. All data processed client-side.</sub>
</p>
