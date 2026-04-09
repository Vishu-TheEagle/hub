# JEE Study Hub v2

A **per-user study dashboard** with JWT authentication, reCAPTCHA protection, and
isolated data for every student. Hosted on Render (free tier).

---

## 📁 Project Structure

```
jee-study-hub/
├── server.js          ← Node.js backend (auth + all APIs)
├── package.json
├── render.yaml        ← Render deployment config
├── public/            ← Static files served by Express
│   ├── index.html     ← Main dashboard SPA
│   ├── Vora-Full-Test-1_ba3b55-1.html
│   ├── Vora-Full-Test-2_a7a995.html
│   ├── Vora-Full-Test-3_fd0a1f.html
│   ├── Vora-Full-Test-4_edc774.html
│   ├── Vora-Full-Test-5_938552.html
│   ├── Vora-Full-Test-6_a5c00a.html
│   ├── Vora-Full-Test-7_8325d0.html
│   ├── Vora-Full-Test-8_eb651d.html
│   ├── Vora-Full-Test-9_48f2e6.html
│   ├── 99-Percentile-Qs-Bank-for-JEE-Main.html
│   ├── Highly-selective-Backlog-Qs-for-JEE-Main-2.html
│   ├── EDUNITI-TOP-75-IN-CBT-3.html
│   ├── Inorganic-Chemistry-Selective-Qs-4.html
│   ├── MUST-DO-PYQs-For-April-2026-5.html
│   └── JEE-Droppers-X2-Batch-1.html
└── data/              ← Auto-created by server (persistent disk on Render)
    └── db.json
```

---

## 🚀 Deploy on Render

### Step 1 — Push to GitHub
1. Create a new GitHub repo.
2. Copy ALL files above into the repo root (keep the `public/` folder).
3. Push to GitHub.

### Step 2 — Create Render Web Service
1. Go to [render.com](https://render.com) → New → Web Service.
2. Connect your GitHub repo.
3. Render will auto-detect `render.yaml`.

### Step 3 — Set Environment Variables on Render
In your Render service → **Environment** tab, set:

| Key                   | Value                                      |
|-----------------------|--------------------------------------------|
| `JWT_SECRET`          | Any long random string (32+ chars)          |
| `RECAPTCHA_SECRET_KEY`| Your Google reCAPTCHA **secret** key        |

### Step 4 — Get reCAPTCHA Keys (Important!)
1. Go to https://www.google.com/recaptcha/admin
2. Register a new site → **reCAPTCHA v2 → "I'm not a robot"**
3. Add your Render URL as an allowed domain (e.g. `jee-study-hub.onrender.com`)
4. Copy the **Site Key** → paste in `public/index.html` (replace both `data-sitekey` values)
5. Copy the **Secret Key** → paste as `RECAPTCHA_SECRET_KEY` env var on Render

> **For local testing only:** The default test key
> `6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI` always passes.
> Do NOT use it in production — anyone can bypass it.

---

## 💻 Run Locally

```bash
npm install
node server.js
# open http://localhost:3000
```

For local dev, reCAPTCHA is bypassed automatically if `RECAPTCHA_SECRET_KEY` is not set.

---

## 🔐 Security Features

| Feature               | Detail                                              |
|-----------------------|-----------------------------------------------------|
| Password hashing      | bcrypt, 12 salt rounds                              |
| JWT tokens            | 7-day expiry, signed with your `JWT_SECRET`         |
| reCAPTCHA v2          | Blocks bots on login + register                     |
| Rate limiting         | 5 register / 10 login per IP per 15 min             |
| Per-user data         | Each user's todos, reminders, notes are isolated    |
| Security headers      | `X-Content-Type-Options`, `X-Frame-Options`, XSS    |

---

## 📡 API Reference

### Auth
| Method | Path                       | Auth? | Description          |
|--------|----------------------------|-------|----------------------|
| POST   | /api/auth/register         | No    | Create account       |
| POST   | /api/auth/login            | No    | Login                |
| GET    | /api/auth/me               | ✅    | Get current user     |
| POST   | /api/auth/change-password  | ✅    | Update password      |

### Per-User Data (all require JWT Bearer token)
| Method | Path                  | Description              |
|--------|-----------------------|--------------------------|
| GET    | /api/todos            | Get all todos            |
| POST   | /api/todos            | Create todo              |
| PUT    | /api/todos/:id        | Update todo              |
| DELETE | /api/todos/:id        | Delete todo              |
| GET    | /api/reminders        | Get all reminders        |
| POST   | /api/reminders        | Create reminder          |
| PUT    | /api/reminders/:id    | Update reminder          |
| DELETE | /api/reminders/:id    | Delete reminder          |
| GET    | /api/progress         | Get progress map         |
| POST   | /api/progress         | Update one item          |
| POST   | /api/progress/sync    | Bulk sync progress       |
| GET    | /api/notes            | Get notes                |
| POST   | /api/notes            | Save notes               |
| GET    | /api/stats            | Get user stats           |

