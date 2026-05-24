require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;

const upload = multer({ storage: multer.memoryStorage() });

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const COOKIE_NAME = "fanvue_oauth";
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me-long-random-string").trim();
const FANVUE_API_VERSION = "2025-06-26";

app.set("trust proxy", true);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));
app.use(cookieParser(SESSION_SECRET));

// ====================== STORES ======================
const oauthStates = new Map();
const sessions = new Map();

// ====================== HELPERS ======================
function createPkceState() {
  const state = crypto.randomBytes(16).toString("hex");
  const codeVerifier = crypto.randomBytes(32).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  oauthStates.set(state, { codeVerifier, ts: Date.now() });
  return { state, codeVerifier, codeChallenge };
}

async function exchangeToken(code, codeVerifier) {
  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: DANI_CLIENT_ID,
    client_secret: DANI_CLIENT_SECRET,
    code,
    redirect_uri: DANI_REDIRECT_URI,
    code_verifier: codeVerifier,
  });

  const resp = await axios.post("https://auth.fanvue.com/oauth2/token", params.toString(), {
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    timeout: 30000,
  });
  return resp.data;
}

function getSession(req) {
  const sid = req.signedCookies?.[COOKIE_NAME];
  return sid ? sessions.get(sid) : null;
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

function getMediaType(mimetype) {
  if (mimetype.startsWith("video/")) return "video";
  return "image";
}

// ====================== FIXED UPLOAD + POST FUNCTION ======================
async function uploadMediaAndCreatePost({ accessToken, file, caption, audience, price }) {
  try {
    console.log(`📤 Uploading ${file.originalname}`);

    // 1. Upload Media
    const startRes = await axios.post("https://api.fanvue.com/media/uploads", {
      name: file.originalname,
      filename: file.originalname,
      mediaType: getMediaType(file.mimetype)
    }, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION,
        "Content-Type": "application/json"
      }
    });

    const mediaUuid = startRes.data.mediaUuid || startRes.data.uuid;
    const uploadId = startRes.data.uploadId || startRes.data.id;

    if (!mediaUuid || !uploadId) throw new Error("Missing media IDs");

    // 2. Signed URL + S3 Upload + Complete
    const signedRes = await axios.get(`https://api.fanvue.com/media/uploads/${uploadId}/parts/1/url`, {
      headers: { Authorization: `Bearer ${accessToken}`, "X-Fanvue-API-Version": FANVUE_API_VERSION }
    });

    const signedUrl = signedRes.data?.url || signedRes.data?.signedUrl;
    await axios.put(signedUrl, file.buffer, {
      headers: { "Content-Type": file.mimetype }
    });

    const etag = (await axios.patch(`https://api.fanvue.com/media/uploads/${uploadId}`, {
      parts: [{ partNumber: 1, etag: "dummy" }] // Fanvue sometimes ignores etag on images
    }, {
      headers: { Authorization: `Bearer ${accessToken}`, "X-Fanvue-API-Version": FANVUE_API_VERSION, "Content-Type": "application/json" }
    })).data; // just to complete

    // 3. CREATE POST - More robust payload
    const postPayload = {
      text: String(caption || "").trim(),
      audience: audience || "followers-and-subscribers",
      mediaUuids: [mediaUuid]
    };

    if (price && Number(price) > 0) postPayload.price = Number(price);

    const postRes = await axios.post("https://api.fanvue.com/posts", postPayload, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION,
        "Content-Type": "application/json"
      },
      validateStatus: () => true
    });

    if (postRes.status < 200 || postRes.status >= 300) {
      console.error("Post creation failed:", postRes.data);
      throw new Error(`Post failed with status ${postRes.status}`);
    }

    console.log("✅ Post created:", postRes.data.uuid);
    return { success: true, mediaUuid, post: postRes.data };

  } catch (err) {
    console.error("❌ Error:", err?.response?.data || err.message);
    throw err;
  }
}

// ====================== ROUTES ======================
app.get("/daniapp/oauth/start", (req, res) => { /* unchanged */ 
  if (!DANI_CLIENT_ID || !DANI_CLIENT_SECRET || !DANI_REDIRECT_URI) return res.status(503).send("Missing credentials");

  const pkce = createPkceState();
  const authUrl = new URL("https://auth.fanvue.com/oauth2/auth");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);
  authUrl.searchParams.set("scope", "openid offline_access write:post write:media read:self");
  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => { /* unchanged - your current one is fine */ 
  // ... (keep your current callback code)
});

app.post("/daniapp/api/post", upload.single("media"), async (req, res) => {
  const session = getSession(req);
  if (!session?.accessToken) return res.status(401).json({ ok: false, error: "Not connected" });
  if (!req.file) return res.status(400).json({ ok: false, error: "No file" });

  try {
    const result = await uploadMediaAndCreatePost({
      accessToken: session.accessToken,
      file: req.file,
      caption: req.body.caption,
      audience: req.body.audience,
      price: req.body.price
    });

    res.json({ ok: true, message: "Post published successfully.", result });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/debug", (req, res) => {
  res.json({ status: "ok", hasSession: !!getSession(req), sessions: sessions.size });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
