// server.cjs — TWO APP SERVER: MidKnight MVP + DaniApp

require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const FormData = require("form-data");

const app = express();
const PORT = process.env.PORT || 10000;

app.set("trust proxy", true);

// ENV
const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || "").trim();
const COOKIE_NAME = (process.env.SESSION_COOKIE_NAME || "fanvue_oauth").trim();
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me-long-random").trim();
const WEBHOOK_SECRET = (process.env.WEBHOOK_SECRET || "").trim();

const FRONTEND_ORIGIN = "https://thesuccessmindset.club";
const FANVUE_AUTH_URL = "https://auth.fanvue.com/oauth2/auth";
const FANVUE_TOKEN_URL = "https://auth.fanvue.com/oauth2/token";
const FANVUE_API_VERSION = "2025-06-26";

// STORES
const oauthStates = new Map();
const sessions = new Map();
const webhookEvents = [];
const MAX_EVENTS = 100;

// UPLOAD
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    if (
      file.mimetype.startsWith("image/") ||
      file.mimetype.startsWith("video/") ||
      file.originalname.toLowerCase().endsWith(".csv") ||
      file.originalname.toLowerCase().endsWith(".xls") ||
      file.originalname.toLowerCase().endsWith(".xlsx")
    ) {
      cb(null, true);
    } else {
      cb(new Error("Unsupported file type"));
    }
  },
});

function rawBodySaver(req, res, buf) {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
}

// CORS FIRST
app.use((req, res, next) => {
  const origin = req.headers.origin;

  if (
    origin === "https://thesuccessmindset.club" ||
    origin === "https://www.thesuccessmindset.club"
  ) {
    res.header("Access-Control-Allow-Origin", origin);
  }

  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Content-Type, x-admin-token");
  res.header("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "25mb", verify: rawBodySaver }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(cookieParser(SESSION_SECRET));

// HELPERS
function baseUrl(req) {
  return `https://${req.get("host")}`;
}

function getSession(req) {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (!sid) return null;
  return sessions.get(sid) || null;
}

function setSessionCookie(res, sid) {
  res.cookie(COOKIE_NAME, sid, {
    signed: true,
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/",
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}

function clearSessionCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "none",
  });
}

function createPkceState() {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  oauthStates.set(state, {
    nonce,
    codeVerifier,
    ts: Date.now(),
  });

  return { state, nonce, codeVerifier, codeChallenge };
}

function redact(value) {
  if (!value) return "";
  const s = String(value);
  if (s.length <= 8) return "***";
  return s.slice(0, 4) + "..." + s.slice(-4);
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return next();
  const got = (req.get("x-admin-token") || "").trim();
  if (got && got === ADMIN_TOKEN) return next();
  return res.status(401).json({ error: "Unauthorized" });
}

function addEvent(evt) {
  webhookEvents.unshift(evt);
  if (webhookEvents.length > MAX_EVENTS) webhookEvents.length = MAX_EVENTS;
}

function verifyFanvueSignature(req) {
  if (!WEBHOOK_SECRET) return { ok: true, reason: "WEBHOOK_SECRET not set" };

  const sig = (req.get("x-fanvue-signature") || "").trim();
  if (!sig) return { ok: false, reason: "missing x-fanvue-signature" };

  const parts = Object.fromEntries(
    sig.split(",").map((kv) => {
      const [k, v] = kv.split("=");
      return [String(k || "").trim(), String(v || "").trim()];
    })
  );

  const t = parts.t;
  const v0 = parts.v0;

  if (!t || !v0) return { ok: false, reason: "signature missing t or v0" };

  const computed = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(`${t}.${req.rawBody || ""}`, "utf8")
    .digest("hex");

  const a = Buffer.from(computed, "hex");
  const b = Buffer.from(v0, "hex");

  if (a.length !== b.length) return { ok: false, reason: "signature length mismatch" };

  return {
    ok: crypto.timingSafeEqual(a, b),
    reason: "checked",
  };
}

function normalizeWebhook(body) {
  const sender = body?.sender || {};

  return {
    type: body?.type || body?.event || "unknown",
    messageUuid: body?.messageUuid || body?.data?.id || body?.id || "",
    recipientUuid:
      body?.recipientUuid ||
      body?.recipient?.uuid ||
      body?.data?.recipientUuid ||
      "",
    senderName: sender?.displayName || sender?.handle || "",
    senderHandle: sender?.handle ? `@${String(sender.handle).replace(/^@/, "")}` : "",
    senderAvatar:
      sender?.avatarUri?.url ||
      sender?.avatarUriSm?.url ||
      sender?.avatarUriXs?.url ||
      "",
    text: body?.data?.text || body?.text || body?.message || "",
  };
}

async function exchangeFanvueToken({ clientId, clientSecret, code, redirectUri, codeVerifier }) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  const tokenResp = await axios.post(
    FANVUE_TOKEN_URL,
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`,
      },
      timeout: 30000,
    }
  );

  return tokenResp.data;
}

async function fetchFanvueProfile(accessToken) {
  const profileResp = await axios.get("https://api.fanvue.com/users/me", {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
    },
    timeout: 30000,
  });

  return profileResp.data || {};
}

function getCreatorName(c) {
  return c?.displayName || c?.name || c?.username || c?.handle || c?.app || "Fanvue Creator";
}

function getCreatorHandle(c) {
  const raw = c?.handle || c?.username || "";
  return raw ? `@${String(raw).replace(/^@/, "")}` : "";
}

function getCreatorAvatar(c) {
  return c?.avatarUrl || c?.avatar_url || c?.avatarUri?.url || c?.avatarUriSm?.url || "";
}

function normalizeAudience(audience) {
  if (audience === "subscribers") return "subscribers";
  return "followers-and-subscribers";
}

function getMediaType(mimetype) {
  return mimetype && mimetype.startsWith("video/") ? "video" : "image";
}

async function uploadMediaToFanvue(accessToken, file) {
  const form = new FormData();

  form.append("file", file.buffer, {
    filename: file.originalname,
    contentType: file.mimetype,
  });

  form.append("type", getMediaType(file.mimetype));

  const resp = await axios.post("https://api.fanvue.com/media", form, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      ...form.getHeaders(),
    },
    timeout: 120000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
  });

  return resp.data;
}

async function createFanvuePost({ accessToken, caption, audience, price, mediaUuid, postNow, scheduleTime }) {
  const payload = {
    caption,
    audience,
    price: Number(price || 0),
    media: [mediaUuid],
  };

  if (!postNow && scheduleTime) {
    payload.scheduleTime = scheduleTime;
  }

  const resp = await axios.post("https://api.fanvue.com/posts", payload, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      "Content-Type": "application/json",
    },
    timeout: 30000,
  });

  return resp.data;
}

async function uploadMediaAndCreatePost({ accessToken, file, caption, audience, price, postNow, scheduleTime }) {
  const media = await uploadMediaToFanvue(accessToken, file);

  const mediaUuid =
    media?.uuid ||
    media?.id ||
    media?.mediaUuid ||
    media?.data?.uuid ||
    media?.data?.id;

  if (!mediaUuid) {
    throw new Error("Media upload succeeded but no media UUID was returned.");
  }

  const post = await createFanvuePost({
    accessToken,
    caption,
    audience,
    price,
    mediaUuid,
    postNow,
    scheduleTime,
  });

  return {
    mediaUuid,
    postUuid: post?.uuid || post?.id || post?.data?.uuid || post?.data?.id || "",
    media,
    post,
  };
}

// CLEANUP
setInterval(() => {
  const now = Date.now();

  for (const [state, data] of oauthStates.entries()) {
    if (now - data.ts > 15 * 60 * 1000) oauthStates.delete(state);
  }

  for (const [sid, data] of sessions.entries()) {
    if (now - data.ts > 30 * 24 * 60 * 60 * 1000) sessions.delete(sid);
  }
}, 60 * 1000);

// DEBUG ROUTES — MUST BE BEFORE STATIC
app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    server: "fanvue-proxy2",
    app: "two-app-server",
    time: new Date().toISOString(),
    env: {
      CLIENT_ID: !!CLIENT_ID,
      CLIENT_ID_PREVIEW: redact(CLIENT_ID),
      CLIENT_SECRET: !!CLIENT_SECRET,
      DANI_CLIENT_ID: !!DANI_CLIENT_ID,
      DANI_CLIENT_ID_PREVIEW: redact(DANI_CLIENT_ID),
      DANI_CLIENT_SECRET: !!DANI_CLIENT_SECRET,
      DANI_REDIRECT_URI,
      COOKIE_NAME,
    },
    sessions: sessions.size,
    states: oauthStates.size,
  });
});

app.get("/daniapp/debug/full", (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  const session = sid ? sessions.get(sid) : null;

  res.json({
    ok: true,
    app: "DaniApp",
    rawCookiePresent: !!req.headers.cookie,
    hasSignedCookie: !!sid,
    signedCookiePreview: redact(sid),
    sessionExists: !!session,
    connected: !!session?.accessToken,
    sessionApp: session?.app || null,
    creator: session?.creator || null,
    sessions: sessions.size,
    states: oauthStates.size,
  });
});

// STATIC ENTRY ROUTES
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.get("/daniapp", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "daniapp", "index.html"));
});

app.get("/daniapp/index.html", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "daniapp", "index.html"));
});

app.get("/health", (req, res) => {
  res.status(200).send("ok");
});

// MIDKNIGHT OAUTH
app.get("/oauth/start", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.status(503).send("Missing CLIENT_ID / CLIENT_SECRET.");
  }

  const pkce = createPkceState();
  const redirectUri = `${baseUrl(req)}/oauth/callback`;
  const authUrl = new URL(FANVUE_AUTH_URL);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("scope", "openid offline_access read:self read:fan read:insights");
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return res.redirect(authUrl.toString());
});

app.get("/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(`Fanvue denied authorization: ${error} ${error_description || ""}`);
  }

  if (!code || !state) return res.status(400).send("Missing code/state");

  const st = oauthStates.get(state);
  if (!st) return res.status(400).send("Invalid/expired state.");

  oauthStates.delete(state);

  try {
    const tokenData = await exchangeFanvueToken({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      code,
      redirectUri: `${baseUrl(req)}/oauth/callback`,
      codeVerifier: st.codeVerifier,
    });

    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error("No access_token returned");

    let creator = {};
    try {
      creator = await fetchFanvueProfile(accessToken);
    } catch {}

    const sid = crypto.randomBytes(24).toString("hex");

    sessions.set(sid, {
      app: "midknight",
      accessToken,
      refreshToken: tokenData.refresh_token || "",
      creator,
      ts: Date.now(),
    });

    setSessionCookie(res, sid);
    return res.redirect("/");
  } catch (err) {
    console.error("MidKnight OAuth failed:", err?.response?.status, err?.response?.data || err.message);
    return res.status(500).send("Authentication failed.");
  }
});

// DANIAPP OAUTH
app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DaniApp OAuth ENV.");
  }

  const pkce = createPkceState();
  const authUrl = new URL(FANVUE_AUTH_URL);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set("scope", "openid offline_access write:post write:media read:self");
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  return res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(`Fanvue denied authorization: ${error} ${error_description || ""}`);
  }

  if (!code || !state) return res.status(400).send("Missing code/state");

  const st = oauthStates.get(state);
  if (!st) return res.status(400).send("Invalid/expired state.");

  oauthStates.delete(state);

  try {
    const tokenData = await exchangeFanvueToken({
      clientId: DANI_CLIENT_ID,
      clientSecret: DANI_CLIENT_SECRET,
      code,
      redirectUri: DANI_REDIRECT_URI,
      codeVerifier: st.codeVerifier,
    });

    const accessToken = tokenData.access_token;
    if (!accessToken) throw new Error("No access_token returned");

    let creator = {
      app: "On My Time",
      connected: true,
    };

    try {
      const profile = await fetchFanvueProfile(accessToken);
      creator = { ...creator, ...profile };
    } catch {}

    const sid = crypto.randomBytes(24).toString("hex");

    sessions.set(sid, {
      app: "daniapp",
      accessToken,
      refreshToken: tokenData.refresh_token || "",
      creator,
      ts: Date.now(),
    });

    setSessionCookie(res, sid);

    const name = encodeURIComponent(getCreatorName(creator) || "Dani Richmond");
    const handle = encodeURIComponent(getCreatorHandle(creator) || "@dani-rich");
    const avatar = encodeURIComponent(getCreatorAvatar(creator) || "");

    return res.redirect(
      `${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&name=${name}&handle=${handle}&avatar=${avatar}`
    );
  } catch (err) {
    console.error("DaniApp OAuth failed:", err?.response?.status, err?.response?.data || err.message);
    return res.status(500).send("DaniApp OAuth failed.");
  }
});

// MIDKNIGHT API
app.get("/api/me", (req, res) => {
  const s = getSession(req);

  if (!s) return res.status(401).json({ error: "Not authenticated" });

  const c = s.creator || {};

  return res.json({
    username: getCreatorName(c),
    handle: getCreatorHandle(c),
    avatar_url: getCreatorAvatar(c),
    raw: c,
  });
});

app.post("/api/logout", (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (sid) sessions.delete(sid);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

// DANIAPP API
app.get("/daniapp/api/me", (req, res) => {
  const s = getSession(req);

  if (!s || s.app !== "daniapp") {
    return res.status(401).json({
      ok: false,
      error: "Not authenticated",
      cookiePresent: !!req.signedCookies?.[COOKIE_NAME],
      sessions: sessions.size,
    });
  }

  return res.json({
    ok: true,
    connected: !!s.accessToken,
    creator: s.creator || {},
  });
});

app.post("/daniapp/logout", (req, res) => {
  const sid = req.signedCookies?.[COOKIE_NAME];
  if (sid) sessions.delete(sid);
  clearSessionCookie(res);
  return res.json({ ok: true });
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  const s = getSession(req);

  if (!s || s.app !== "daniapp" || !s.accessToken) {
    return res.status(401).json({
      ok: false,
      error: "Fanvue is not connected. Reconnect Fanvue first.",
      debug: {
        cookiePresent: !!req.signedCookies?.[COOKIE_NAME],
        sessions: sessions.size,
        sessionApp: s?.app || null,
      },
    });
  }

  if (!req.file) {
    return res.status(400).json({
      ok: false,
      error: "No media file uploaded.",
    });
  }

  try {
    const result = await uploadMediaAndCreatePost({
      accessToken: s.accessToken,
      file: req.file,
      caption: String(req.body.caption || "").trim(),
      audience: normalizeAudience(req.body.audience),
      price: req.body.price || "0",
      postNow: req.body.postNow === "true",
      scheduleTime: req.body.scheduleTime || "",
    });

    return res.json({
      ok: true,
      message: req.body.postNow === "true" ? "Posted successfully." : "Scheduled successfully.",
      ...result,
    });
  } catch (err) {
    console.error("DaniApp post failed:", err?.response?.status, err?.response?.data || err.message);

    return res.status(500).json({
      ok: false,
      error: "Fanvue post failed.",
      details: err?.response?.data || err.message,
    });
  }
});

// WEBHOOKS
app.get("/webhooks/fanvue", (req, res) => {
  res.status(200).send("ok");
});

app.post("/webhooks/fanvue", (req, res) => {
  const ver = verifyFanvueSignature(req);

  if (!ver.ok) {
    console.warn("Webhook rejected:", ver.reason);
    return res.status(401).send("invalid signature");
  }

  const receivedAt = new Date().toISOString();
  const normalized = normalizeWebhook(req.body);

  const evt = {
    receivedAt,
    normalized,
    body: req.body,
  };

  addEvent(evt);

  return res.status(200).send("ok");
});

app.get("/api/events", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });

  return res.json({
    count: webhookEvents.length,
    events: webhookEvents,
  });
});

app.get("/api/events/last", (req, res) => {
  const s = getSession(req);
  if (!s) return res.status(401).json({ error: "Not authenticated" });

  return res.json(webhookEvents[0] || null);
});

app.post("/api/events/clear", requireAdmin, (req, res) => {
  webhookEvents.length = 0;
  return res.json({ ok: true });
});

// STATIC LAST
app.use(express.static(path.join(__dirname, "public")));

// FALLBACK LAST
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "dashboard.html"));
});

app.listen(PORT, () => {
  console.log("============================================================");
  console.log("SERVER READY");
  console.log("Dashboard: https://fanvue-proxy2.onrender.com/");
  console.log("Dani OAuth: https://fanvue-proxy2.onrender.com/daniapp/oauth/start");
  console.log("Env Check: https://fanvue-proxy2.onrender.com/env-check");
  console.log("Dani Debug: https://fanvue-proxy2.onrender.com/daniapp/debug/full");
  console.log("============================================================");
});
