require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const multer = require("multer");
const FormData = require("form-data");

const app = express();
const PORT = process.env.PORT || 10000;

const BASE_URL = (process.env.BASE_URL || "https://fanvue-proxy2.onrender.com").trim();
const FRONTEND_ORIGIN = "https://thesuccessmindset.club";

const OAUTH_CLIENT_ID = (process.env.OAUTH_CLIENT_ID || "").trim();
const OAUTH_CLIENT_SECRET = (process.env.OAUTH_CLIENT_SECRET || "").trim();
const OAUTH_REDIRECT_URI =
  (process.env.OAUTH_REDIRECT_URI || `${BASE_URL}/api/oauth/callback`).trim();
const OAUTH_SCOPES =
  (process.env.OAUTH_SCOPES || "read:self read:chat read:creator read:fan write:chat").trim();

const DANI_CLIENT_ID =
  (process.env.DANI_CLIENT_ID || process.env.OAUTH_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET =
  (process.env.DANI_CLIENT_SECRET || process.env.OAUTH_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI =
  (process.env.DANI_REDIRECT_URI || `${BASE_URL}/daniapp/oauth/callback`).trim();
const DANI_SCOPES =
  (process.env.DANI_SCOPES || "openid offline_access write:post write:media read:self").trim();

const AUTH_BASE = (process.env.OAUTH_ISSUER_BASE_URL || "https://auth.fanvue.com").trim();
const API_BASE = (process.env.API_BASE_URL || "https://api.fanvue.com").trim();
const FANVUE_API_VERSION = "2025-06-26";

const sessions = new Map();
const oauthStates = new Map();
const webhookEvents = [];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 }
});

app.set("trust proxy", true);

app.use(cors({
  origin(origin, cb) {
    if (!origin) return cb(null, true);
    if (
      origin === FRONTEND_ORIGIN ||
      origin === "https://www.thesuccessmindset.club" ||
      origin === BASE_URL
    ) return cb(null, true);
    return cb(null, true);
  },
  credentials: true,
  allowedHeaders: ["Content-Type", "x-dani-session", "x-mvp-session"],
  methods: ["GET", "POST", "OPTIONS"]
}));

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

function makeState(appName) {
  const state = crypto.randomBytes(16).toString("hex");
  oauthStates.set(state, { appName, created: Date.now() });
  return state;
}

function makeSession(data) {
  const sid = crypto.randomBytes(24).toString("hex");
  sessions.set(sid, { ...data, created: Date.now() });
  return sid;
}

function getSession(req) {
  const sid =
    req.get("x-dani-session") ||
    req.get("x-mvp-session") ||
    req.query.sid ||
    "";
  return { sid, session: sid ? sessions.get(sid) : null };
}

function safeProfileName(p) {
  return p?.displayName || p?.name || p?.username || p?.handle || "Fanvue Creator";
}

function safeHandle(p) {
  const raw = p?.handle || p?.username || "";
  return raw ? "@" + String(raw).replace(/^@/, "") : "";
}

function safeAvatar(p) {
  return p?.avatarUrl || p?.avatar_url || p?.avatarUri?.url || p?.avatarUriSm?.url || "";
}

async function exchangeToken({ clientId, clientSecret, redirectUri, code }) {
  const response = await axios.post(
    `${AUTH_BASE}/oauth/token`,
    new URLSearchParams({
      grant_type: "authorization_code",
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      code
    }).toString(),
    {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      timeout: 30000
    }
  );

  return response.data;
}

async function getProfile(accessToken) {
  const response = await axios.get(`${API_BASE}/users/me`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION
    },
    timeout: 30000
  });

  return response.data || {};
}

async function uploadMedia(accessToken, file) {
  const form = new FormData();

  form.append("file", file.buffer, {
    filename: file.originalname,
    contentType: file.mimetype
  });

  form.append("type", file.mimetype.startsWith("video/") ? "video" : "image");

  const response = await axios.post(`${API_BASE}/media`, form, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      ...form.getHeaders()
    },
    timeout: 120000,
    maxBodyLength: Infinity,
    maxContentLength: Infinity
  });

  return response.data;
}

async function createPost(accessToken, body) {
  const response = await axios.post(`${API_BASE}/posts`, body, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      "Content-Type": "application/json"
    },
    timeout: 30000
  });

  return response.data;
}

app.get("/", (req, res) => {
  res.send(`
    <body style="background:#111;color:white;font-family:Arial;padding:40px">
      <h1>MidKnight VIP Services OAuth Server Running</h1>
      <p><a href="/oauth/start" style="color:#ff1493">MidKnight Login</a></p>
      <p><a href="/daniapp/oauth/start" style="color:#ff1493">DaniApp Login</a></p>
      <p><a href="/env-check" style="color:#ff1493">Env Check</a></p>
    </body>
  `);
});

app.get("/health", (req, res) => res.send("ok"));

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "two-app-functional-server",
    baseUrl: BASE_URL,
    mvp: {
      client: !!OAUTH_CLIENT_ID,
      secret: !!OAUTH_CLIENT_SECRET,
      redirect: OAUTH_REDIRECT_URI,
      scopes: OAUTH_SCOPES
    },
    daniapp: {
      client: !!DANI_CLIENT_ID,
      secret: !!DANI_CLIENT_SECRET,
      redirect: DANI_REDIRECT_URI,
      scopes: DANI_SCOPES
    },
    sessions: sessions.size,
    states: oauthStates.size
  });
});

/* MIDKNIGHT MVP */

app.get("/oauth/start", (req, res) => {
  const state = makeState("mvp");
  const url = new URL(`${AUTH_BASE}/oauth/authorize`);

  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", OAUTH_CLIENT_ID);
  url.searchParams.set("redirect_uri", OAUTH_REDIRECT_URI);
  url.searchParams.set("scope", OAUTH_SCOPES);
  url.searchParams.set("state", state);

  res.redirect(url.toString());
});

app.get("/api/oauth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) return res.status(400).send(String(error));
    if (!code || !state) return res.status(400).send("Missing OAuth code/state");

    const st = oauthStates.get(state);
    if (!st || st.appName !== "mvp") return res.status(400).send("Invalid state");

    oauthStates.delete(state);

    const tokens = await exchangeToken({
      clientId: OAUTH_CLIENT_ID,
      clientSecret: OAUTH_CLIENT_SECRET,
      redirectUri: OAUTH_REDIRECT_URI,
      code
    });

    let profile = {};
    try {
      profile = await getProfile(tokens.access_token);
    } catch {}

    const sid = makeSession({
      app: "mvp",
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || "",
      profile
    });

    res.send(`
      <h1>MidKnight OAuth Success</h1>
      <p>Session ID:</p>
      <pre>${sid}</pre>
      <p>Profile:</p>
      <pre>${JSON.stringify(profile, null, 2)}</pre>
    `);
  } catch (err) {
    console.error("MVP OAuth error:", err?.response?.data || err.message);
    res.status(500).send("OAuth callback failed");
  }
});

app.get("/api/me", (req, res) => {
  const { session } = getSession(req);
  if (!session) return res.status(401).json({ ok: false, error: "Not authenticated" });
  res.json({ ok: true, app: session.app, profile: session.profile || {} });
});

app.post("/api/logout", (req, res) => {
  const { sid } = getSession(req);
  if (sid) sessions.delete(sid);
  res.json({ ok: true });
});

/* DANIAPP */

app.get("/daniapp/oauth/start", (req, res) => {
  const state = makeState("daniapp");
  const url = new URL(`${AUTH_BASE}/oauth/authorize`);

  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", DANI_CLIENT_ID);
  url.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  url.searchParams.set("scope", DANI_SCOPES);
  url.searchParams.set("state", state);

  res.redirect(url.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) return res.status(400).send(String(error));
    if (!code || !state) return res.status(400).send("Missing OAuth code/state");

    const st = oauthStates.get(state);
    if (!st || st.appName !== "daniapp") return res.status(400).send("Invalid state");

    oauthStates.delete(state);

    const tokens = await exchangeToken({
      clientId: DANI_CLIENT_ID,
      clientSecret: DANI_CLIENT_SECRET,
      redirectUri: DANI_REDIRECT_URI,
      code
    });

    let profile = {};
    try {
      profile = await getProfile(tokens.access_token);
    } catch {}

    const sid = makeSession({
      app: "daniapp",
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || "",
      profile
    });

    const name = encodeURIComponent(safeProfileName(profile));
    const handle = encodeURIComponent(safeHandle(profile) || "@dani-rich");
    const avatar = encodeURIComponent(safeAvatar(profile));

    res.redirect(
      `${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`
    );
  } catch (err) {
    console.error("Dani OAuth error:", err?.response?.data || err.message);
    res.status(500).send("DaniApp OAuth failed");
  }
});

app.get("/daniapp/debug/full", (req, res) => {
  const { sid, session } = getSession(req);
  res.json({
    ok: true,
    sidPresent: !!sid,
    sessionExists: !!session,
    connected: !!session?.accessToken,
    app: session?.app || null,
    profile: session?.profile || null,
    sessions: sessions.size
  });
});

app.get("/daniapp/api/me", (req, res) => {
  const { session } = getSession(req);
  if (!session || session.app !== "daniapp") {
    return res.status(401).json({ ok: false, error: "Not connected" });
  }
  res.json({ ok: true, profile: session.profile || {} });
});

app.post("/daniapp/logout", (req, res) => {
  const { sid } = getSession(req);
  if (sid) sessions.delete(sid);
  res.json({ ok: true });
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);

    if (!session || session.app !== "daniapp") {
      return res.status(401).json({
        ok: false,
        error: "Fanvue is not connected. Reconnect Fanvue first."
      });
    }

    if (!req.file) {
      return res.status(400).json({ ok: false, error: "No media uploaded" });
    }

    const media = await uploadMedia(session.accessToken, req.file);
    const mediaId = media?.uuid || media?.id || media?.data?.uuid || media?.data?.id;

    if (!mediaId) {
      return res.status(500).json({
        ok: false,
        error: "Media upload returned no ID",
        media
      });
    }

    const postPayload = {
      caption: String(req.body.caption || "").trim(),
      audience: req.body.audience || "followers-and-subscribers",
      price: Number(req.body.price || 0),
      media: [mediaId]
    };

    if (req.body.postNow !== "true" && req.body.scheduleTime) {
      postPayload.scheduleTime = req.body.scheduleTime;
    }

    const post = await createPost(session.accessToken, postPayload);

    res.json({
      ok: true,
      message: req.body.postNow === "true" ? "Posted successfully" : "Scheduled successfully",
      mediaId,
      post
    });
  } catch (err) {
    console.error("Dani post error:", err?.response?.data || err.message);
    res.status(500).json({
      ok: false,
      error: "Fanvue post failed",
      details: err?.response?.data || err.message
    });
  }
});

app.post("/daniapp/api/bulk-post", (req, res) => {
  res.json({ ok: true, message: "Bulk route alive" });
});

/* WEBHOOK EVENTS */

app.post("/webhooks/fanvue", (req, res) => {
  webhookEvents.unshift({
    receivedAt: new Date().toISOString(),
    body: req.body
  });
  if (webhookEvents.length > 100) webhookEvents.length = 100;
  res.send("ok");
});

app.get("/api/events", (req, res) => {
  res.json({ count: webhookEvents.length, events: webhookEvents });
});

app.listen(PORT, () => {
  console.log("============================================================");
  console.log("FULL TWO-APP FANVUE SERVER READY");
  console.log(`Port: ${PORT}`);
  console.log(`MVP OAuth: ${BASE_URL}/oauth/start`);
  console.log(`MVP Callback: ${OAUTH_REDIRECT_URI}`);
  console.log(`Dani OAuth: ${BASE_URL}/daniapp/oauth/start`);
  console.log(`Dani Callback: ${DANI_REDIRECT_URI}`);
  console.log(`Env Check: ${BASE_URL}/env-check`);
  console.log("============================================================");
});
