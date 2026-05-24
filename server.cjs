require("dotenv").config();

const express = require("express");
const cors = require("cors");
const axios = require("axios");
const crypto = require("crypto");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;

const BASE_URL = process.env.BASE_URL || "https://fanvue-proxy2.onrender.com";
const FRONTEND_ORIGIN = "https://thesuccessmindset.club";

const AUTH_BASE = process.env.OAUTH_ISSUER_BASE_URL || "https://auth.fanvue.com";
const API_BASE = process.env.API_BASE_URL || "https://api.fanvue.com";
const FANVUE_API_VERSION = "2025-06-26";

const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "";
const OAUTH_REDIRECT_URI = process.env.OAUTH_REDIRECT_URI || `${BASE_URL}/oauth/callback`;
const OAUTH_SCOPES = process.env.OAUTH_SCOPES || "read:self read:chat read:creator read:fan write:chat";

const DANI_CLIENT_ID = process.env.DANI_CLIENT_ID || "";
const DANI_CLIENT_SECRET = process.env.DANI_CLIENT_SECRET || "";
const DANI_REDIRECT_URI = process.env.DANI_REDIRECT_URI || `${BASE_URL}/daniapp/oauth/callback`;
const DANI_SCOPES = process.env.DANI_SCOPES || "read:chat read:creator read:fan read:insights read:media read:self read:post write:chat write:creator write:media write:post read:tracking_links write:tracking_links read:agency write:agency";

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
  return profile?.displayName || profile?.name || profile?.username || profile?.handle || "Fanvue Creator";
}

function getHandle(profile) {
  const raw = profile?.handle || profile?.username || "";
  return raw ? "@" + String(raw).replace(/^@/, "") : "";
}

function getAvatar(profile) {
  return profile?.avatarUrl || profile?.avatar_url || profile?.avatarUri?.url || profile?.avatarUriSm?.url || "";
}

function getMediaType(file) {
  if (file.mimetype.startsWith("video/")) return "video";
  if (file.mimetype.startsWith("audio/")) return "audio";
  if (file.mimetype.includes("pdf")) return "document";
  return "image";
}

async function exchangeToken({ clientId, clientSecret, redirectUri, code, codeVerifier }) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

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

// ==================== FIXED UPLOAD FUNCTIONS ====================

async function createUploadSession(accessToken, file) {
  const response = await axios.post(
    `${API_BASE}/media/uploads`,
    {
      name: file.originalname,
      filename: file.originalname,
      mimeType: file.mimetype,
      size: file.size,
      mediaType: getMediaType(file)
    },
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "create_upload_session",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.data;
}

async function getSignedUploadUrl(accessToken, uploadId) {
  const response = await axios.post(
    `${API_BASE}/media/uploads/${uploadId}/url`,
    {},
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "get_signed_upload_url",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.data.url;
}

async function completeUploadSession(accessToken, uploadId) {
  const response = await axios.post(
    `${API_BASE}/media/uploads/${uploadId}/complete`,
    {},
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "complete_upload_session",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.data;
}

async function uploadMediaFanvue(accessToken, file) {
  const start = await createUploadSession(accessToken, file);

  const uploadId = start.uploadId || start.id || start.uuid;
  const mediaUuid = start.mediaUuid || start.media?.uuid || start.uuid;

  if (!uploadId) {
    throw { stage: "create_upload_session", details: start };
  }

  const signedUrl = await getSignedUploadUrl(accessToken, uploadId);

  await axios.put(signedUrl, file.buffer, {
    headers: { "Content-Type": file.mimetype },
    maxBodyLength: Infinity,
    maxContentLength: Infinity,
    validateStatus: () => true
  });

  await completeUploadSession(accessToken, uploadId);

  return { mediaUuid, uploadId };
}

// ==================== END UPLOAD FUNCTIONS ====================

async function createUserPost(accessToken, payload) {
  const response = await axios.post(
    `${API_BASE}/creator/posts`,
    payload,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION,
        "Content-Type": "application/json"
      },
      timeout: 30000,
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "create_post",
      status: response.status,
      details: response.data,
      payloadSent: payload
    };
  }

  return response.data;
}

setInterval(() => {
  const now = Date.now();
  for (const [state, value] of oauthStates.entries()) {
    if (now - value.created > 15 * 60 * 1000) oauthStates.delete(state);
  }
  for (const [sid, value] of sessions.entries()) {
    if (now - value.created > 30 * 24 * 60 * 60 * 1000) sessions.delete(sid);
  }
}, 60 * 1000);

// ====================== ROUTES ======================

app.get("/", (req, res) => {
  res.send(`<body style="background:#111;color:white;font-family:Arial;padding:40px"><h1>Fanvue Server Running</h1></body>`);
});

app.get("/health", (req, res) => res.send("ok"));

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "two-app-creator-upload-session-v2",
    daniapp: { client: !!DANI_CLIENT_ID },
    endpoints: {
      createUploadSession: `${API_BASE}/media/uploads`
    },
    sessions: sessions.size
  });
});

app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing DaniApp OAuth variables.");
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

    if (error) return res.status(400).send(`OAuth error: ${error} ${error_description || ""}`);
    if (!code || !state) return res.status(400).send("Missing code or state");

    const stored = oauthStates.get(state);
    if (!stored || stored.appName !== "daniapp") return res.status(400).send("Invalid state");

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
    } catch (e) {
      console.error("Profile fetch failed:", e.message);
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

    res.redirect(`${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`);
  } catch (err) {
    console.error("DaniApp OAuth failed:", err?.response?.data || err.message);
    res.status(500).send("OAuth failed. Please try again.");
  }
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req);

    if (!session || session.app !== "daniapp" || !session.accessToken) {
      return res.status(401).json({ ok: false, error: "Fanvue is not connected." });
    }

    if (!req.file) {
      return res.status(400).json({ ok: false, error: "No media uploaded" });
    }

    const uploadResult = await uploadMediaFanvue(session.accessToken, req.file);

    const postPayload = {
      audience: req.body.audience || "followers-and-subscribers",
      text: String(req.body.caption || "").trim(),
      mediaUuids: [uploadResult.mediaUuid]
    };

    if (Number(req.body.price) > 0) postPayload.price = Number(req.body.price);
    if (req.body.postNow !== "true" && req.body.scheduleTime) {
      postPayload.publishAt = new Date(req.body.scheduleTime).toISOString();
    }

    const post = await createUserPost(session.accessToken, postPayload);

    return res.json({
      ok: true,
      mediaUuid: uploadResult.mediaUuid,
      post
    });
  } catch (err) {
    console.error("Post failed:", err);
    return res.status(500).json({
      ok: false,
      error: "Fanvue post failed",
      stage: err.stage || "unknown",
      details: err.details || err.message
    });
  }
});

app.post("/daniapp/logout", (req, res) => {
  const { sid } = getSession(req);
  if (sid) sessions.delete(sid);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("============================================================");
  console.log("FANVUE SERVER READY - FIXED UPLOAD v2");
  console.log(`Env Check: ${BASE_URL}/env-check`);
  console.log("============================================================");
});
