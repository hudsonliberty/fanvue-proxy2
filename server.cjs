require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const multer = require("multer");
const FormData = require("form-data");

const app = express();
const PORT = process.env.PORT || 10000;

const BASE_URL = process.env.BASE_URL || "https://fanvue-proxy2.onrender.com";
const FRONTEND_ORIGIN = "https://thesuccessmindset.club";

const AUTH_BASE = process.env.OAUTH_ISSUER_BASE_URL || "https://auth.fanvue.com";
const API_BASE = process.env.API_BASE_URL || "https://api.fanvue.com";
const FANVUE_API_VERSION = "2025-06-26";

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const OAUTH_REDIRECT_URI =
  process.env.OAUTH_REDIRECT_URI || `${BASE_URL}/oauth/callback`;
const OAUTH_SCOPES =
  process.env.OAUTH_SCOPES || "read:self read:chat read:creator read:fan write:chat";

const DANI_CLIENT_ID = process.env.DANI_CLIENT_ID || "";
const DANI_CLIENT_SECRET = process.env.DANI_CLIENT_SECRET || "";
const DANI_REDIRECT_URI =
  process.env.DANI_REDIRECT_URI || `${BASE_URL}/daniapp/oauth/callback`;
const DANI_SCOPES =
  process.env.DANI_SCOPES || "openid offline_access write:post write:media read:self";

const sessions = new Map();
const oauthStates = new Map();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 }
});

app.set("trust proxy", true);

app.use(cors({
  origin: true,
  credentials: true,
  allowedHeaders: ["Content-Type", "x-dani-session", "x-mvp-session"],
  methods: ["GET", "POST", "OPTIONS"]
}));

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

function createPkceState(appName) {
  const state = crypto.randomBytes(16).toString("hex");
  const nonce = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  oauthStates.set(state, {
    appName,
    nonce,
    codeVerifier,
    created: Date.now()
  });

  return { state, nonce, codeVerifier, codeChallenge };
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

  return {
    sid,
    session: sid ? sessions.get(sid) : null
  };
}

function getName(profile) {
  return (
    profile?.displayName ||
    profile?.name ||
    profile?.username ||
    profile?.handle ||
    "Fanvue Creator"
  );
}

function getHandle(profile) {
  const raw = profile?.handle || profile?.username || "";
  return raw ? "@" + String(raw).replace(/^@/, "") : "";
}

function getAvatar(profile) {
  return (
    profile?.avatarUrl ||
    profile?.avatar_url ||
    profile?.avatarUri?.url ||
    profile?.avatarUriSm?.url ||
    profile?.avatarUriXs?.url ||
    ""
  );
}

async function exchangeToken({ clientId, clientSecret, redirectUri, code, codeVerifier }) {
  const basicAuth = Buffer
    .from(`${clientId}:${clientSecret}`)
    .toString("base64");

  const response = await axios.post(
    `${AUTH_BASE}/oauth2/token`,
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier
    }).toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`
      },
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

async function createPost(accessToken, payload) {
  const response = await axios.post(`${API_BASE}/posts`, payload, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "X-Fanvue-API-Version": FANVUE_API_VERSION,
      "Content-Type": "application/json"
    },
    timeout: 30000
  });

  return response.data;
}

setInterval(() => {
  const now = Date.now();

  for (const [state, value] of oauthStates.entries()) {
    if (now - value.created > 15 * 60 * 1000) {
      oauthStates.delete(state);
    }
  }

  for (const [sid, value] of sessions.entries()) {
    if (now - value.created > 30 * 24 * 60 * 60 * 1000) {
      sessions.delete(sid);
    }
  }
}, 60 * 1000);

app.get("/", (req, res) => {
  res.send(`
    <body style="background:#111;color:white;font-family:Arial;padding:40px">
      <h1>Fanvue Two-App Server Running</h1>
      <p><a style="color:#ff1493" href="/oauth/start">MidKnight Login</a></p>
      <p><a style="color:#ff1493" href="/daniapp/oauth/start">DaniApp Login</a></p>
      <p><a style="color:#ff1493" href="/env-check">Env Check</a></p>
    </body>
  `);
});

app.get("/health", (req, res) => {
  res.send("ok");
});

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "two-app-render-pkce-basic-auth",
    midknight: {
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
    endpoints: {
      auth: `${AUTH_BASE}/oauth2/auth`,
      token: `${AUTH_BASE}/oauth2/token`,
      api: API_BASE
    },
    sessions: sessions.size,
    states: oauthStates.size
  });
});

/* MIDKNIGHT APP */

app.get("/oauth/start", (req, res) => {
  if (!OAUTH_CLIENT_ID || !OAUTH_CLIENT_SECRET || !OAUTH_REDIRECT_URI) {
    return res.status(503).send("Missing MidKnight OAuth environment variables.");
  }

  const pkce = createPkceState("midknight");
  const authUrl = new URL(`${AUTH_BASE}/oauth2/auth`);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", OAUTH_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", OAUTH_REDIRECT_URI);
  authUrl.searchParams.set("scope", OAUTH_SCOPES);
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`MidKnight OAuth error: ${error} ${error_description || ""}`);
    }

    if (!code || !state) {
      return res.status(400).send("Missing code/state");
    }

    const stored = oauthStates.get(state);

    if (!stored || stored.appName !== "midknight") {
      return res.status(400).send("Invalid MidKnight state");
    }

    oauthStates.delete(state);

    const tokens = await exchangeToken({
      clientId: OAUTH_CLIENT_ID,
      clientSecret: OAUTH_CLIENT_SECRET,
      redirectUri: OAUTH_REDIRECT_URI,
      code,
      codeVerifier: stored.codeVerifier
    });

    let profile = {};

    try {
      profile = await getProfile(tokens.access_token);
    } catch (err) {
      console.error("MidKnight profile fetch failed:", err?.response?.data || err.message);
    }

    const sid = makeSession({
      app: "midknight",
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || "",
      profile
    });

    res.send(`
      <body style="background:#111;color:white;font-family:Arial;padding:40px">
        <h1>MidKnight OAuth Success</h1>
        <p>Session ID:</p>
        <pre>${sid}</pre>
        <p>Profile:</p>
        <pre>${JSON.stringify(profile, null, 2)}</pre>
      </body>
    `);
  } catch (err) {
    console.error("MidKnight OAuth failed:", err?.response?.data || err.message);
    res.status(500).send("MidKnight OAuth failed");
  }
});

app.get("/api/me", (req, res) => {
  const { session } = getSession(req);

  if (!session) {
    return res.status(401).json({
      ok: false,
      error: "Not authenticated"
    });
  }

  res.json({
    ok: true,
    app: session.app,
    profile: session.profile || {}
  });
});

app.post("/api/logout", (req, res) => {
  const { sid } = getSession(req);

  if (sid) {
    sessions.delete(sid);
  }

  res.json({ ok: true });
});

/* DANIAPP */

app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DaniApp OAuth environment variables.");
  }

  const pkce = createPkceState("daniapp");
  const authUrl = new URL(`${AUTH_BASE}/oauth2/auth`);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set("scope", DANI_SCOPES);
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("nonce", pkce.nonce);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`DaniApp OAuth error: ${error} ${error_description || ""}`);
    }

    if (!code || !state) {
      return res.status(400).send("Missing code/state");
    }

    const stored = oauthStates.get(state);

    if (!stored || stored.appName !== "daniapp") {
      return res.status(400).send("Invalid DaniApp state");
    }

    oauthStates.delete(state);

    const tokens = await exchangeToken({
      clientId: DANI_CLIENT_ID,
      clientSecret: DANI_CLIENT_SECRET,
      redirectUri: DANI_REDIRECT_URI,
      code,
      codeVerifier: stored.codeVerifier
    });

    let profile = {};

    try {
      profile = await getProfile(tokens.access_token);
    } catch (err) {
      console.error("DaniApp profile fetch failed:", err?.response?.data || err.message);
    }

    const sid = makeSession({
      app: "daniapp",
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token || "",
      profile
    });

    const name = encodeURIComponent(getName(profile) || "Dani Richmond");
    const handle = encodeURIComponent(getHandle(profile) || "@dani-rich");
    const avatar = encodeURIComponent(getAvatar(profile) || "");

    res.redirect(
      `${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`
    );
  } catch (err) {
    console.error("DaniApp OAuth failed:", err?.response?.data || err.message);
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
    sessions: sessions.size,
    states: oauthStates.size
  });
});

app.get("/daniapp/api/me", (req, res) => {
  const { session } = getSession(req);

  if (!session || session.app !== "daniapp") {
    return res.status(401).json({
      ok: false,
      error: "Not connected"
    });
  }

  res.json({
    ok: true,
    connected: true,
    profile: session.profile || {}
  });
});

app.post("/daniapp/logout", (req, res) => {
  const { sid } = getSession(req);

  if (sid) {
    sessions.delete(sid);
  }

  res.json({ ok: true });
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);

    if (!session || session.app !== "daniapp" || !session.accessToken) {
      return res.status(401).json({
        ok: false,
        error: "Fanvue is not connected. Reconnect Fanvue first."
      });
    }

    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "No media uploaded"
      });
    }

    const media = await uploadMedia(session.accessToken, req.file);

    const mediaId =
      media?.uuid ||
      media?.id ||
      media?.mediaUuid ||
      media?.data?.uuid ||
      media?.data?.id;

    if (!mediaId) {
      return res.status(500).json({
        ok: false,
        error: "Media upload returned no ID",
        media
      });
    }

    const payload = {
      caption: String(req.body.caption || "").trim(),
      audience: req.body.audience || "followers-and-subscribers",
      price: Number(req.body.price || 0),
      media: [mediaId]
    };

    if (req.body.postNow !== "true" && req.body.scheduleTime) {
      payload.scheduleTime = req.body.scheduleTime;
    }

    const post = await createPost(session.accessToken, payload);

    res.json({
      ok: true,
      message: req.body.postNow === "true" ? "Posted successfully" : "Scheduled successfully",
      mediaId,
      post
    });
  } catch (err) {
    console.error("Dani post failed:", err?.response?.data || err.message);

    res.status(500).json({
      ok: false,
      error: "Fanvue post failed",
      details: err?.response?.data || err.message
    });
  }
});

app.post("/daniapp/api/bulk-post", (req, res) => {
  res.json({
    ok: true,
    message: "Bulk route alive"
  });
});

app.listen(PORT, () => {
  console.log("============================================================");
  console.log("TWO APP FANVUE SERVER READY - PKCE BASIC AUTH LOCKED");
  console.log(`MidKnight OAuth: ${BASE_URL}/oauth/start`);
  console.log(`MidKnight Callback: ${OAUTH_REDIRECT_URI}`);
  console.log(`DaniApp OAuth: ${BASE_URL}/daniapp/oauth/start`);
  console.log(`DaniApp Callback: ${DANI_REDIRECT_URI}`);
  console.log(`Env Check: ${BASE_URL}/env-check`);
  console.log("============================================================");
});
