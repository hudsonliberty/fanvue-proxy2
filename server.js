Got it. **Username + profile must show immediately after login.**
To do that cleanly, the **GUI must be served from the same Render app** (so the OAuth session cookie works). Otherwise cPanel (thesuccessmindset.club) can’t read Render cookies and you’ll keep getting “logged in but nothing shows”.

Below is the **drop-in plumbing** (2 files) that does exactly this:

* ✅ OAuth login
* ✅ Stores tokens server-side
* ✅ `/api/me` returns **creator username + avatar**
* ✅ GUI shows **name + handle + profile image** after login

---

## 1) Render `server.js` (DROP-IN)

Replace your Render repo `server.js` with this:

```js
import express from "express";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(cookieParser());

/** ===== ENV ===== **/
const {
  OAUTH_CLIENT_ID,
  OAUTH_CLIENT_SECRET,
  OAUTH_REDIRECT_URI, // MUST be https://fanvue-proxy2.onrender.com/oauth/callback
  OAUTH_SCOPES = "openid offline_access read:self",
  OAUTH_ISSUER_BASE_URL = "https://auth.fanvue.com",
  API_BASE_URL = "https://api.fanvue.com",
  SESSION_COOKIE_NAME = "mv_session",
  SESSION_SECRET = "change_me",
  PORT = 3000
} = process.env;

/** ===== In-memory session store (MVP) ===== **/
const SESS = new Map(); // sid -> { access_token, refresh_token, expires_at }

function sign(val) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(val).digest("hex");
}

function setSessionCookie(res, sid) {
  const sig = sign(sid);
  res.cookie(SESSION_COOKIE_NAME, `${sid}.${sig}`, {
    httpOnly: true,
    sameSite: "lax",
    secure: true,
    path: "/"
  });
}

function readSession(req) {
  const raw = req.cookies[SESSION_COOKIE_NAME];
  if (!raw) return null;
  const [sid, sig] = raw.split(".");
  if (!sid || !sig) return null;
  if (sign(sid) !== sig) return null;
  return SESS.get(sid) || null;
}

function clearSession(req, res) {
  const raw = req.cookies[SESSION_COOKIE_NAME];
  if (raw) {
    const [sid] = raw.split(".");
    if (sid) SESS.delete(sid);
  }
  res.clearCookie(SESSION_COOKIE_NAME, { path: "/" });
}

/** ===== Helpers ===== **/
async function tokenExchange(code) {
  // Fanvue requires client_secret_basic
  const basic = Buffer.from(`${OAUTH_CLIENT_ID}:${OAUTH_CLIENT_SECRET}`).toString("base64");

  const body = new URLSearchParams();
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", OAUTH_REDIRECT_URI);

  const r = await fetch(`${OAUTH_ISSUER_BASE_URL}/connect/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) {
    const err = new Error("token_exchange_failed");
    err.detail = j;
    throw err;
  }
  return j;
}

async function fanvueMe(accessToken) {
  // Endpoint name may differ
```
