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

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const MIDKNIGHT_CLIENT_ID = (process.env.MIDKNIGHT_CLIENT_ID || "").trim();
const MIDKNIGHT_CLIENT_SECRET = (process.env.MIDKNIGHT_CLIENT_SECRET || "").trim();
const MIDKNIGHT_REDIRECT_URI = (process.env.MIDKNIGHT_REDIRECT_URI || "").trim();

const FANVUE_API_VERSION = "2025-06-26";

app.set("trust proxy", true);

app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://thesuccessmindset.club");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Content-Type, x-dani-session, x-midknight-session");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true, limit: "50mb" }));

// ======================================================
// STORES
// ======================================================

const oauthStates = new Map();
const sessions = new Map();

// ======================================================
// HELPERS
// ======================================================

function createPkceState(appName) {
  const state = crypto.randomBytes(16).toString("hex");

  const codeVerifier = crypto
    .randomBytes(32)
    .toString("base64url");

  const codeChallenge = crypto
    .createHash("sha256")
    .update(codeVerifier)
    .digest("base64url");

  oauthStates.set(state, {
    appName,
    codeVerifier,
    ts: Date.now()
  });

  return {
    state,
    codeVerifier,
    codeChallenge
  };
}

function makeSession(data) {
  const sid = crypto
    .randomBytes(24)
    .toString("hex");

  sessions.set(sid, {
    ...data,
    ts: Date.now()
  });

  return sid;
}

function getSession(req, type = "dani") {

  const sid =
    type === "midknight"
      ? (
          req.get("x-midknight-session") ||
          req.query.sid ||
          req.body?.sid ||
          ""
        )
      : (
          req.get("x-dani-session") ||
          req.query.sid ||
          req.body?.sid ||
          ""
        );

  return sid ? sessions.get(sid) : null;
}

function getMediaType(mimetype) {
  if (mimetype.startsWith("video/")) return "video";
  if (mimetype.startsWith("audio/")) return "audio";
  return "image";
}

async function exchangeToken({
  clientId,
  clientSecret,
  redirectUri,
  code,
  codeVerifier
}) {

  const basicAuth = Buffer
    .from(`${clientId}:${clientSecret}`)
    .toString("base64");

  const params = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: codeVerifier
  });

  const resp = await axios.post(
    "https://auth.fanvue.com/oauth2/token",
    params.toString(),
    {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basicAuth}`
      },
      timeout: 30000
    }
  );

  return resp.data;
}

async function getProfile(accessToken) {

  const response = await axios.get(
    "https://api.fanvue.com/users/me",
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-Fanvue-API-Version": FANVUE_API_VERSION
      },
      timeout: 30000
    }
  );

  return response.data;
}

// ======================================================
// UPLOAD + POST
// ======================================================

async function uploadMediaAndCreatePost({
  accessToken,
  file,
  caption,
  audience,
  price,
  postNow,
  scheduleTime
}) {

  try {

    console.log("=================================================");
    console.log("📤 STARTING MEDIA UPLOAD");
    console.log("=================================================");

    // ==================================================
    // 1. CREATE UPLOAD SESSION
    // ==================================================

    const startRes = await axios.post(
      "https://api.fanvue.com/media/uploads",
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
        validateStatus: () => true
      }
    );

    console.log("UPLOAD SESSION STATUS:", startRes.status);
    console.log("UPLOAD SESSION DATA:", startRes.data);

    if (
      startRes.status !== 200 &&
      startRes.status !== 201
    ) {
      throw new Error(
        `Upload session failed: ${startRes.status} ${JSON.stringify(startRes.data)}`
      );
    }

    const mediaUuid =
      startRes.data.mediaUuid ||
      startRes.data.uuid ||
      startRes.data.id;

    const uploadId =
      startRes.data.uploadId ||
      startRes.data.id;

    if (!mediaUuid || !uploadId) {
      throw new Error("Missing mediaUuid or uploadId");
    }

    // ==================================================
    // 2. GET SIGNED URL
    // ==================================================

    const signedRes = await axios.get(
      `https://api.fanvue.com/media/uploads/${uploadId}/parts/1/url`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "X-Fanvue-API-Version": FANVUE_API_VERSION
        },
        validateStatus: () => true
      }
    );

    console.log("SIGNED URL STATUS:", signedRes.status);
    console.log("SIGNED URL DATA:", signedRes.data);

    // ==================================================
    // FIX FOR STRING URL RESPONSE
    // ==================================================

    let signedUrl = null;

    if (typeof signedRes.data === "string") {
      signedUrl = signedRes.data;
    } else {
      signedUrl =
        signedRes.data?.url ||
        signedRes.data?.signedUrl ||
        signedRes.data?.uploadUrl;
    }

    if (!signedUrl) {
      throw new Error(
        `No signed upload URL received: ${JSON.stringify(signedRes.data)}`
      );
    }

    // ==================================================
    // 3. PUT FILE TO S3
    // ==================================================

    const putRes = await axios.put(
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

    console.log("PUT STATUS:", putRes.status);

    if (
      putRes.status < 200 ||
      putRes.status >= 300
    ) {
      throw new Error(
        `S3 upload failed: ${putRes.status}`
      );
    }

    const etag =
      putRes.headers.etag ||
      putRes.headers.ETag ||
      "1";

    // ==================================================
    // 4. COMPLETE UPLOAD
    // ==================================================

    const completeRes = await axios.patch(
      `https://api.fanvue.com/media/uploads/${uploadId}`,
      {
        parts: [
          {
            partNumber: 1,
            etag
          }
        ]
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "X-Fanvue-API-Version": FANVUE_API_VERSION,
          "Content-Type": "application/json"
        },
        validateStatus: () => true
      }
    );

    console.log("COMPLETE STATUS:", completeRes.status);
    console.log("COMPLETE DATA:", completeRes.data);

    // ==================================================
    // 5. CREATE POST
    // ==================================================

    const postPayload = {
      text: String(caption || "").trim(),
      audience: audience || "followers-and-subscribers",
      mediaUuids: [mediaUuid]
    };

    if (
      price &&
      Number(price) > 0
    ) {
      postPayload.price = Number(price);
    }

    if (
      postNow !== "true" &&
      scheduleTime
    ) {
      postPayload.publishAt =
        new Date(scheduleTime).toISOString();
    }

    console.log("POST PAYLOAD:", postPayload);

    const postRes = await axios.post(
      "https://api.fanvue.com/posts",
      postPayload,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "X-Fanvue-API-Version": FANVUE_API_VERSION,
          "Content-Type": "application/json"
        },
        validateStatus: () => true
      }
    );

    console.log("POST STATUS:", postRes.status);
    console.log("POST DATA:", postRes.data);

    if (
      postRes.status < 200 ||
      postRes.status >= 300
    ) {
      throw new Error(
        `Post creation failed: ${postRes.status} ${JSON.stringify(postRes.data)}`
      );
    }

    return {
      success: true,
      mediaUuid,
      uploadId,
      upload: completeRes.data,
      post: postRes.data
    };

  } catch (err) {

    console.error("=================================================");
    console.error("❌ UPLOAD / POST ERROR");
    console.error("=================================================");

    if (err.response) {
      console.error("STATUS:", err.response.status);
      console.error("DATA:", err.response.data);
    } else {
      console.error(err.message);
    }

    throw err;
  }
}

// ======================================================
// ROOT
// ======================================================

app.get("/", (req, res) => {
  res.send("Fanvue Server Running");
});

app.get("/health", (req, res) => {
  res.send("ok");
});

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    build: "fanvue-signed-url-fix-final",
    sessions: sessions.size,
    states: oauthStates.size,
    apiVersion: FANVUE_API_VERSION
  });
});

app.get("/daniapp/debug/full", (req, res) => {

  const session = getSession(req, "dani");

  res.json({
    ok: true,
    connected: !!session?.accessToken,
    sessionExists: !!session,
    profile: session?.profile || null,
    sessions: sessions.size
  });
});

// ======================================================
// DANI OAUTH
// ======================================================

app.get("/daniapp/oauth/start", (req, res) => {

  const pkce = createPkceState("dani");

  const authUrl = new URL(
    "https://auth.fanvue.com/oauth2/auth"
  );

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", DANI_REDIRECT_URI);

  authUrl.searchParams.set(
    "scope",
    "openid offline_access write:post write:media read:self"
  );

  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/daniapp/oauth/callback", async (req, res) => {

  try {

    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(error);
    }

    const stored = oauthStates.get(state);

    if (!stored) {
      return res.status(400).send("Invalid state");
    }

    oauthStates.delete(state);

    const tokenData = await exchangeToken({
      clientId: DANI_CLIENT_ID,
      clientSecret: DANI_CLIENT_SECRET,
      redirectUri: DANI_REDIRECT_URI,
      code,
      codeVerifier: stored.codeVerifier
    });

    const profile = await getProfile(
      tokenData.access_token
    );

    const sid = makeSession({
      type: "dani",
      accessToken: tokenData.access_token,
      profile
    });

    const name = encodeURIComponent(
      profile.displayName || "Dani Richmond"
    );

    const handle = encodeURIComponent(
      `@${(profile.handle || "").replace("@", "")}`
    );

    const avatar = encodeURIComponent(
      profile.avatarUrl || ""
    );

    res.redirect(
      `https://thesuccessmindset.club/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`
    );

  } catch (err) {

    console.error(
      err?.response?.data || err.message
    );

    res.status(500).send("OAuth failed");
  }
});

// ======================================================
// MIDKNIGHT OAUTH
// ======================================================

app.get("/midknight/oauth/start", (req, res) => {

  const pkce = createPkceState("midknight");

  const authUrl = new URL(
    "https://auth.fanvue.com/oauth2/auth"
  );

  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", MIDKNIGHT_CLIENT_ID);
  authUrl.searchParams.set("redirect_uri", MIDKNIGHT_REDIRECT_URI);

  authUrl.searchParams.set(
    "scope",
    "openid offline_access write:post write:media read:self"
  );

  authUrl.searchParams.set("state", pkce.state);
  authUrl.searchParams.set("code_challenge", pkce.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  res.redirect(authUrl.toString());
});

app.get("/midknight/oauth/callback", async (req, res) => {

  try {

    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).send(error);
    }

    const stored = oauthStates.get(state);

    if (!stored) {
      return res.status(400).send("Invalid state");
    }

    oauthStates.delete(state);

    const tokenData = await exchangeToken({
      clientId: MIDKNIGHT_CLIENT_ID,
      clientSecret: MIDKNIGHT_CLIENT_SECRET,
      redirectUri: MIDKNIGHT_REDIRECT_URI,
      code,
      codeVerifier: stored.codeVerifier
    });

    const profile = await getProfile(
      tokenData.access_token
    );

    const sid = makeSession({
      type: "midknight",
      accessToken: tokenData.access_token,
      profile
    });

    res.json({
      ok: true,
      sid,
      profile
    });

  } catch (err) {

    console.error(
      err?.response?.data || err.message
    );

    res.status(500).send("OAuth failed");
  }
});

// ======================================================
// SINGLE POST
// ======================================================

app.post(
  "/daniapp/api/post",
  upload.single("media"),
  async (req, res) => {

    try {

      const session = getSession(req, "dani");

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

      const result =
        await uploadMediaAndCreatePost({
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

      res.status(500).json({
        ok: false,
        error:
          err?.response?.data ||
          err.message
      });
    }
  }
);

// ======================================================
// BULK POST
// ======================================================

app.post(
  "/daniapp/api/bulk-post",
  upload.array("media", 50),
  async (req, res) => {

    try {

      const session = getSession(req, "dani");

      if (!session?.accessToken) {
        return res.status(401).json({
          ok: false,
          error: "Fanvue not connected"
        });
      }

      if (!req.files?.length) {
        return res.status(400).json({
          ok: false,
          error: "No media files"
        });
      }

      const results = [];

      for (const file of req.files) {

        try {

          const result =
            await uploadMediaAndCreatePost({
              accessToken: session.accessToken,
              file,
              caption: req.body.caption || "",
              audience:
                req.body.audience ||
                "followers-and-subscribers",
              price: req.body.price || 0,
              postNow: "true"
            });

          results.push({
            success: true,
            file: file.originalname,
            result
          });

        } catch (err) {

          results.push({
            success: false,
            file: file.originalname,
            error:
              err?.response?.data ||
              err.message
          });
        }
      }

      res.json({
        ok: true,
        total: results.length,
        results
      });

    } catch (err) {

      res.status(500).json({
        ok: false,
        error:
          err?.response?.data ||
          err.message
      });
    }
  }
);

// ======================================================
// LOGOUT
// ======================================================

app.post("/daniapp/logout", (req, res) => {

  const sid =
    req.get("x-dani-session") ||
    req.body?.sid ||
    "";

  if (sid) {
    sessions.delete(sid);
  }

  res.json({
    ok: true
  });
});

// ======================================================
// START
// ======================================================

app.listen(PORT, () => {

  console.log("=================================================");
  console.log("🚀 FANVUE SERVER RUNNING");
  console.log("=================================================");
  console.log(`PORT: ${PORT}`);
  console.log("=================================================");
});
