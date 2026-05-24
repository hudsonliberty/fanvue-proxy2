require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 200 * 1024 * 1024 }
});

const BASE_URL = (process.env.BASE_URL || "https://fanvue-proxy2.onrender.com").trim();
const FRONTEND_ORIGIN = "https://thesuccessmindset.club";

const FANVUE_API_VERSION = "2025-06-26";
const AUTH_BASE = "https://auth.fanvue.com";
const API_BASE = "https://api.fanvue.com";

const CLIENT_ID = (process.env.CLIENT_ID || "").trim();
const CLIENT_SECRET = (process.env.CLIENT_SECRET || "").trim();
const OAUTH_REDIRECT_URI = (process.env.OAUTH_REDIRECT_URI || `${BASE_URL}/oauth/callback`).trim();

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || `${BASE_URL}/daniapp/oauth/callback`).trim();

const ADMIN_TOKEN = (process.env.ADMIN_TOKEN || "").trim();

const MIDKNIGHT_SCOPES = (
  process.env.OAUTH_SCOPES ||
  "openid offline_access read:self read:chat read:creator read:fan write:chat write:post write:media"
).replace(/^"|"$/g, "").trim();

const DANI_SCOPES = (
  process.env.DANI_SCOPES ||
  "read:chat read:creator read:fan read:insights read:media read:self read:post write:chat write:creator write:media write:post read:tracking_links write:tracking_links read:agency write:agency"
).replace(/^"|"$/g, "").trim();

const oauthStates = new Map();
const sessions = new Map();
const webhookEvents = [];
const settings = { enabled: false };

app.set("trust proxy", true);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", FRONTEND_ORIGIN);
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Content-Type, x-dani-session, x-midknight-session, x-admin-token");
  res.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

  if (req.method === "OPTIONS") return res.sendStatus(204);

  next();
});

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return next();

  const got = ((req.get("x-admin-token") || "").trim() || (req.query.token || "").trim());

  if (got === ADMIN_TOKEN) return next();

  return res.status(401).json({
    ok: false,
    error: "Unauthorized"
  });
}

function createPkceState(appName) {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  oauthStates.set(state, {
    appName,
    codeVerifier,
    ts: Date.now()
  });

  return { state, codeVerifier, codeChallenge };
}

function makeSession(data) {
  const sid = crypto.randomBytes(24).toString("hex");

  sessions.set(sid, {
    ...data,
    ts: Date.now()
  });

  return sid;
}

function getSession(req, type = "any") {
  const sid =
    type === "midknight"
      ? req.get("x-midknight-session") || req.query.sid || req.body?.sid || ""
      : type === "dani"
      ? req.get("x-dani-session") || req.query.sid || req.body?.sid || ""
      : req.get("x-dani-session") ||
        req.get("x-midknight-session") ||
        req.query.sid ||
        req.body?.sid ||
        "";

  return {
    sid,
    session: sid ? sessions.get(sid) : null
  };
}

function getMediaType(mimetype) {
  if (mimetype.startsWith("video/")) return "video";
  if (mimetype.startsWith("audio/")) return "audio";
  return "image";
}

function getName(profile, fallback) {
  return profile?.displayName || profile?.name || profile?.username || profile?.handle || fallback;
}

function getHandle(profile) {
  const raw = profile?.handle || profile?.username || "";
  return raw ? `@${String(raw).replace(/^@/, "")}` : "";
}

function getAvatar(profile) {
  return (
    profile?.avatarUrl ||
    profile?.avatar_url ||
    profile?.avatarUri?.url ||
    profile?.avatarUriSm?.url ||
    ""
  );
}

async function exchangeToken({ clientId, clientSecret, redirectUri, code, codeVerifier }) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  });

  const response = await axios.post(
    `${AUTH_BASE}/oauth2/token`,
    params.toString(),
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

async function createUploadSession({ accessToken, file }) {
  const response = await axios.post(
    `${API_BASE}/media/uploads`,
    {
      name: file.originalname,
      filename: file.originalname,
      mediaType: getMediaType(file.mimetype)
    },
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
      stage: "create_upload_session",
      status: response.status,
      details: response.data
    };
  }

  const mediaUuid = response.data?.mediaUuid || response.data?.uuid || response.data?.id;
  const uploadId = response.data?.uploadId || response.data?.id;

  if (!mediaUuid || !uploadId) {
    throw {
      stage: "create_upload_session",
      status: 500,
      details: {
        error: "Missing mediaUuid or uploadId",
        response: response.data
      }
    };
  }

  return {
    mediaUuid,
    uploadId,
    raw: response.data
  };
}

async function getSignedUploadUrl({ accessToken, uploadId }) {
  const response = await axios.get(
    `${API_BASE}/media/uploads/${uploadId}/parts/1/url`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      timeout: 30000,
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "get_signed_upload_url",
      status: response.status,
      details: response.data
    };
  }

  let signedUrl = null;

  if (typeof response.data === "string") {
    signedUrl = response.data;
  } else {
    signedUrl =
      response.data?.url ||
      response.data?.signedUrl ||
      response.data?.uploadUrl ||
      response.data?.data?.url ||
      response.data?.data?.signedUrl ||
      response.data?.data?.uploadUrl;
  }

  if (!signedUrl) {
    throw {
      stage: "get_signed_upload_url",
      status: 500,
      details: {
        error: "No signed upload URL received",
        response: response.data
      }
    };
  }

  return signedUrl;
}

async function uploadToSignedUrl({ signedUrl, file }) {
  const response = await axios.put(
    signedUrl,
    file.buffer,
    {
      headers: {
        "Content-Type": file.mimetype
      },
      timeout: 120000,
      maxBodyLength: Infinity,
      maxContentLength: Infinity,
      validateStatus: () => true
    }
  );

  if (response.status < 200 || response.status >= 300) {
    throw {
      stage: "s3_put_upload",
      status: response.status,
      details: response.data || response.statusText
    };
  }

  return response.headers.etag || response.headers.ETag || "1";
}

async function completeUpload({ accessToken, uploadId, etag }) {
  const response = await axios.patch(
    `${API_BASE}/media/uploads/${uploadId}`,
    {
      parts: [
        {
          PartNumber: 1,
          ETag: etag
        }
      ]
    },
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
      stage: "complete_upload",
      status: response.status,
      details: response.data
    };
  }

  return response.data;
}

async function createFanvuePost({
  accessToken,
  caption,
  audience,
  price,
  mediaUuid,
  postNow,
  scheduleTime
}) {
  const payload = {
    text: String(caption || "").trim(),
    audience: audience || "followers-and-subscribers",
    mediaUuids: [mediaUuid]
  };

  if (price && Number(price) > 0) payload.price = Number(price);

  if (postNow !== "true" && scheduleTime) {
    payload.publishAt = new Date(scheduleTime).toISOString();
  }

  const response = await axios.post(
    `${API_BASE}/posts`,
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

async function uploadMediaAndCreatePost({
  accessToken,
  file,
  caption,
  audience,
  price,
  postNow,
  scheduleTime
}) {
  const started = await createUploadSession({ accessToken, file });

  const signedUrl = await getSignedUploadUrl({
    accessToken,
    uploadId: started.uploadId
  });

  const etag = await uploadToSignedUrl({ signedUrl, file });

  const completed = await completeUpload({
    accessToken,
    uploadId: started.uploadId,
    etag
  });

  const post = await createFanvuePost({
    accessToken,
    caption,
    audience,
    price,
    mediaUuid: started.mediaUuid,
    postNow,
    scheduleTime
  });

  return {
    success: true,
    mediaUuid: started.mediaUuid,
    uploadId: started.uploadId,
    upload: completed,
    post
  };
}

app.get("/", (req, res) => {
  res.send("Fanvue Two-App Server Running");
});

app.get("/health", (req, res) => {
  res.send("ok");
});

app.get("/debug", (req, res) => {
  res.json({
    ok: true,
    sessions: sessions.size,
    states: oauthStates.size,
    build: "two-app-midknight-dani-bulk-restored"
  });
});

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "two-app-midknight-dani-bulk-restored",
    routes: {
      midknightStart: "/auth/fanvue",
      midknightCallback: "/oauth/callback",
      daniStart: "/daniapp/oauth/start",
      daniCallback: "/daniapp/oauth/callback",
      daniPost: "/daniapp/api/post",
      daniBulk: "/daniapp/api/bulk-post",
      webhook: "/webhooks/fanvue"
    },
    midknight: {
      client: !!CLIENT_ID,
      secret: !!CLIENT_SECRET,
      redirect: OAUTH_REDIRECT_URI,
      scopes: MIDKNIGHT_SCOPES
    },
    dani: {
      client: !!DANI_CLIENT_ID,
      secret: !!DANI_CLIENT_SECRET,
      redirect: DANI_REDIRECT_URI,
      scopes: DANI_SCOPES
    },
    sessions: sessions.size,
    states: oauthStates.size
  });
});

app.get("/daniapp/debug/full", (req, res) => {
  const { sid, session } = getSession(req, "dani");

  res.json({
    ok: true,
    sidPresent: !!sid,
    sessionExists: !!session,
    connected: !!session?.accessToken,
    profile: session?.profile || null,
    sessions: sessions.size
  });
});

app.get("/oauth/status", requireAdmin, (req, res) => {
  const midknightSessions = [...sessions.values()].filter(s => s.type === "midknight").length;

  res.json({
    ok: true,
    authed: midknightSessions > 0,
    midknightSessions,
    totalSessions: sessions.size
  });
});

app.get("/settings", requireAdmin, (req, res) => {
  res.json({
    ok: true,
    enabled: settings.enabled
  });
});

app.post("/settings", requireAdmin, (req, res) => {
  settings.enabled = !!req.body?.enabled;

  res.json({
    ok: true,
    enabled: settings.enabled
  });
});

app.get("/auth/fanvue", (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET || !OAUTH_REDIRECT_URI) {
    return res.status(503).send("Missing MidKnight OAuth credentials.");
  }

  const pkce = createPkceState("midknight");

  const authUrl = new URL(`${AUTH_BASE}/oauth2/auth`);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", OAUTH_REDIRECT_URI);
  authUrl.searchParams.set("scope", MIDKNIGHT_SCOPES);
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/midknight/oauth/start", (req, res) => {
  res.redirect("/auth/fanvue");
});

app.get("/oauth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`OAuth Error: ${error} ${error_description || ""}`);
    }

    if (!code || !state) {
      return res.status(400).send("Missing code or state");
    }

    const stored = oauthStates.get(state);

    if (!stored || stored.appName !== "midknight") {
      return res.status(400).send("Invalid MidKnight state");
    }

    oauthStates.delete(state);

    const tokenData = await exchangeToken({
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri: OAUTH_REDIRECT_URI,
      code,
      codeVerifier: stored.codeVerifier
    });

    let profile = {};

    try {
      profile = await getProfile(tokenData.access_token);
    } catch {
      profile = {};
    }

    const sid = makeSession({
      type: "midknight",
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token || "",
      profile
    });

    res.redirect(
      `${FRONTEND_ORIGIN}/midknight-vip-services/?connected=1&sid=${sid}`
    );
  } catch (err) {
    console.error("MidKnight OAuth failed:", err?.response?.data || err.message);

    res.status(500).send("MidKnight OAuth failed");
  }
});

app.get("/daniapp/oauth/start", (req, res) => {
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) {
    return res.status(503).send("Missing Dani OAuth credentials.");
  }

  const pkce = createPkceState("dani");

  const authUrl = new URL(`${AUTH_BASE}/oauth2/auth`);

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set("scope", DANI_SCOPES);
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`OAuth Error: ${error} ${error_description || ""}`);
    }

    if (!code || !state) {
      return res.status(400).send("Missing code or state");
    }

    const stored = oauthStates.get(state);

    if (!stored || stored.appName !== "dani") {
      return res.status(400).send("Invalid Dani state");
    }

    oauthStates.delete(state);

    const tokenData = await exchangeToken({
      clientId: DANI_CLIENT_ID,
      clientSecret: DANI_CLIENT_SECRET,
      redirectUri: DANI_REDIRECT_URI,
      code,
      codeVerifier: stored.codeVerifier
    });

    const profile = await getProfile(tokenData.access_token);

    const sid = makeSession({
      type: "dani",
      accessToken: tokenData.access_token,
      refreshToken: tokenData.refresh_token || "",
      profile
    });

    const name = encodeURIComponent(getName(profile, "Dani Richmond"));
    const handle = encodeURIComponent(getHandle(profile));
    const avatar = encodeURIComponent(getAvatar(profile));

    res.redirect(
      `${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`
    );
  } catch (err) {
    console.error("Dani OAuth failed:", err?.response?.data || err.message);

    res.status(500).send("Dani OAuth failed");
  }
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  try {
    const { session } = getSession(req, "dani");

    if (!session?.accessToken) {
      return res.status(401).json({
        ok: false,
        error: "Fanvue not connected"
      });
    }

    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "No media file"
      });
    }

    const result = await uploadMediaAndCreatePost({
      accessToken: session.accessToken,
      file: req.file,
      caption: req.body.caption,
      audience: req.body.audience,
      price: req.body.price,
      postNow: req.body.postNow,
      scheduleTime: req.body.scheduleTime
    });

    res.json({
      ok: true,
      message: "Post published successfully.",
      result
    });
  } catch (err) {
    console.error("Dani post error:", err?.response?.data || err.message || err);

    res.status(500).json({
      ok: false,
      stage: err.stage || "unknown",
      status: err.status || 500,
      error: err?.response?.data || err.details || err.message || err
    });
  }
});

app.post("/daniapp/api/bulk-post", upload.array("media", 50), async (req, res) => {
  try {
    const { session } = getSession(req, "dani");

    if (!session?.accessToken) {
      return res.status(401).json({
        ok: false,
        error: "Fanvue not connected"
      });
    }

    if (!req.files || !req.files.length) {
      return res.status(400).json({
        ok: false,
        error: "No media files uploaded"
      });
    }

    const results = [];

    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      try {
        const result = await uploadMediaAndCreatePost({
          accessToken: session.accessToken,
          file,
          caption: Array.isArray(req.body.caption)
            ? req.body.caption[i] || ""
            : req.body.caption || "",
          audience: req.body.audience || "followers-and-subscribers",
          price: Array.isArray(req.body.price)
            ? req.body.price[i] || 0
            : req.body.price || 0,
          postNow: req.body.postNow || "true",
          scheduleTime: Array.isArray(req.body.scheduleTime)
            ? req.body.scheduleTime[i] || ""
            : req.body.scheduleTime || ""
        });

        results.push({
          success: true,
          file: file.originalname,
          mediaUuid: result.mediaUuid,
          uploadId: result.uploadId,
          post: result.post
        });
      } catch (err) {
        results.push({
          success: false,
          file: file.originalname,
          error: err?.response?.data || err.details || err.message || err
        });
      }
    }

    res.json({
      ok: true,
      total: results.length,
      successCount: results.filter(r => r.success).length,
      failedCount: results.filter(r => !r.success).length,
      results
    });
  } catch (err) {
    console.error("Bulk route error:", err?.response?.data || err.message || err);

    res.status(500).json({
      ok: false,
      error: err?.response?.data || err.message || "Bulk upload failed"
    });
  }
});

app.post("/daniapp/logout", (req, res) => {
  const sid =
    req.get("x-dani-session") ||
    req.body?.sid ||
    req.query.sid ||
    "";

  if (sid) {
    sessions.delete(sid);
  }

  res.json({ ok: true });
});

app.get("/webhooks/fanvue", (req, res) => {
  res.status(200).send("ok");
});

app.post("/webhooks/fanvue", (req, res) => {
  const evt = {
    receivedAt: new Date().toISOString(),
    body: req.body
  };

  webhookEvents.unshift(evt);

  if (webhookEvents.length > 100) webhookEvents.length = 100;

  res.status(200).json({
    ok: true,
    received: true,
    enabled: settings.enabled
  });
});

app.get("/api/events", requireAdmin, (req, res) => {
  res.json({
    ok: true,
    count: webhookEvents.length,
    events: webhookEvents
  });
});

app.listen(PORT, () => {
  console.log("=================================================");
  console.log("FANVUE TWO-APP SERVER RUNNING");
  console.log(`PORT: ${PORT}`);
  console.log(`MidKnight OAuth: ${BASE_URL}/auth/fanvue`);
  console.log(`MidKnight Callback: ${OAUTH_REDIRECT_URI}`);
  console.log(`Dani OAuth: ${BASE_URL}/daniapp/oauth/start`);
  console.log(`Dani Callback: ${DANI_REDIRECT_URI}`);
  console.log("=================================================");
});
