require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 10000;

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 200 * 1024 * 1024
  }
});

const DANI_CLIENT_ID = (process.env.DANI_CLIENT_ID || "").trim();
const DANI_CLIENT_SECRET = (process.env.DANI_CLIENT_SECRET || "").trim();
const DANI_REDIRECT_URI = (process.env.DANI_REDIRECT_URI || "").trim();

const MIDKNIGHT_CLIENT_ID = (process.env.MIDKNIGHT_CLIENT_ID || "").trim();
const MIDKNIGHT_CLIENT_SECRET = (process.env.MIDKNIGHT_CLIENT_SECRET || "").trim();
const MIDKNIGHT_REDIRECT_URI = (process.env.MIDKNIGHT_REDIRECT_URI || "").trim();

const FANVUE_API_VERSION = "2025-06-26";

const FRONTEND_ORIGIN = "https://thesuccessmindset.club";

app.set("trust proxy", true);

app.use((req, res, next) => {
  res.header(
    "Access-Control-Allow-Origin",
    "https://thesuccessmindset.club"
  );

  res.header(
    "Access-Control-Allow-Credentials",
    "true"
  );

  res.header(
    "Access-Control-Allow-Headers",
    "Content-Type,x-dani-session,x-midknight-session"
  );

  res.header(
    "Access-Control-Allow-Methods",
    "GET,POST,OPTIONS"
  );

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({
  limit: "50mb"
}));

app.use(express.urlencoded({
  extended: true,
  limit: "50mb"
}));

// ====================== STORES ======================

const oauthStates = new Map();
const sessions = new Map();

// ====================== HELPERS ======================

function createPkceState(appName) {

  const state =
    crypto.randomBytes(16).toString("hex");

  const codeVerifier =
    crypto.randomBytes(32).toString("base64url");

  const codeChallenge =
    crypto
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

  const sid =
    crypto.randomBytes(24).toString("hex");

  sessions.set(sid, {
    ...data,
    ts: Date.now()
  });

  return sid;
}

function getSession(req) {

  const sid =
    req.get("x-dani-session") ||
    req.get("x-midknight-session") ||
    req.query.sid ||
    req.body?.sid ||
    "";

  return sid
    ? sessions.get(sid)
    : null;
}

function getMediaType(mimetype) {

  if (
    mimetype.startsWith("video/")
  ) {
    return "video";
  }

  if (
    mimetype.startsWith("audio/")
  ) {
    return "audio";
  }

  return "image";
}

async function exchangeToken({
  clientId,
  clientSecret,
  redirectUri,
  code,
  codeVerifier
}) {

  const params =
    new URLSearchParams({
      grant_type:
        "authorization_code",
      client_id:
        clientId,
      client_secret:
        clientSecret,
      code,
      redirect_uri:
        redirectUri,
      code_verifier:
        codeVerifier
    });

  const resp =
    await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      params.toString(),
      {
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        timeout: 30000
      }
    );

  return resp.data;
}

async function getProfile(
  accessToken
) {

  const resp =
    await axios.get(
      "https://api.fanvue.com/users/me",
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
          "X-Fanvue-API-Version":
            FANVUE_API_VERSION
        },
        timeout: 30000
      }
    );

  return resp.data;
}

// ====================== FANVUE CORE ======================

async function createUploadSession({
  accessToken,
  file
}) {

  const resp =
    await axios.post(
      "https://api.fanvue.com/media/uploads",
      {
        name:
          file.originalname,
        filename:
          file.originalname,
        mediaType:
          getMediaType(
            file.mimetype
          )
      },
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
          "X-Fanvue-API-Version":
            FANVUE_API_VERSION,
          "Content-Type":
            "application/json"
        },
        timeout: 30000
      }
    );

  return resp.data;
}

async function getSignedUploadUrl({
  accessToken,
  uploadId
}) {

  const resp =
    await axios.get(
      `https://api.fanvue.com/media/uploads/${uploadId}/parts/1/url`,
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
          "X-Fanvue-API-Version":
            FANVUE_API_VERSION
        },
        timeout: 30000
      }
    );

  return (
    resp.data?.url ||
    resp.data?.signedUrl
  );
}

async function uploadToSignedUrl({
  signedUrl,
  file
}) {

  const resp =
    await axios.put(
      signedUrl,
      file.buffer,
      {
        headers: {
          "Content-Type":
            file.mimetype
        },
        timeout: 120000
      }
    );

  return (
    resp.headers.etag ||
    resp.headers.ETag ||
    "1"
  );
}

async function completeUpload({
  accessToken,
  uploadId,
  etag
}) {

  const resp =
    await axios.patch(
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
          Authorization:
            `Bearer ${accessToken}`,
          "X-Fanvue-API-Version":
            FANVUE_API_VERSION,
          "Content-Type":
            "application/json"
        },
        timeout: 30000
      }
    );

  return resp.data;
}

async function createPost({
  accessToken,
  caption,
  audience,
  price,
  mediaUuid
}) {

  const payload = {
    text:
      String(
        caption || ""
      ).trim(),

    audience:
      audience ||
      "followers-and-subscribers",

    media: [
      {
        uuid:
          mediaUuid
      }
    ]
  };

  if (
    price &&
    Number(price) > 0
  ) {

    payload.price =
      Number(price);
  }

  const resp =
    await axios.post(
      "https://api.fanvue.com/posts",
      payload,
      {
        headers: {
          Authorization:
            `Bearer ${accessToken}`,
          "X-Fanvue-API-Version":
            FANVUE_API_VERSION,
          "Content-Type":
            "application/json"
        },
        timeout: 30000
      }
    );

  return resp.data;
}

async function uploadMediaAndCreatePost({
  accessToken,
  file,
  caption,
  audience,
  price
}) {

  console.log(
    `📤 Uploading ${file.originalname}`
  );

  const start =
    await createUploadSession({
      accessToken,
      file
    });

  const mediaUuid =
    start.mediaUuid ||
    start.uuid;

  const uploadId =
    start.uploadId ||
    start.id;

  if (
    !mediaUuid ||
    !uploadId
  ) {

    throw new Error(
      "Missing mediaUuid or uploadId"
    );
  }

  const signedUrl =
    await getSignedUploadUrl({
      accessToken,
      uploadId
    });

  if (!signedUrl) {

    throw new Error(
      "No signed URL returned"
    );
  }

  const etag =
    await uploadToSignedUrl({
      signedUrl,
      file
    });

  await completeUpload({
    accessToken,
    uploadId,
    etag
  });

  const post =
    await createPost({
      accessToken,
      caption,
      audience,
      price,
      mediaUuid
    });

  return {
    success: true,
    mediaUuid,
    uploadId,
    post
  };
}

// ====================== BULK UPLOAD ======================

async function processBulkUploads({
  accessToken,
  files,
  caption,
  audience,
  price
}) {

  const results = [];

  for (const file of files) {

    try {

      const result =
        await uploadMediaAndCreatePost({
          accessToken,
          file,
          caption,
          audience,
          price
        });

      results.push({
        file:
          file.originalname,
        success: true,
        result
      });

    } catch (err) {

      results.push({
        file:
          file.originalname,
        success: false,
        error:
          err?.response?.data ||
          err.message
      });
    }
  }

  return results;
}

// ====================== ROUTES ======================

app.get("/", (req, res) => {

  res.send(
    "Fanvue Dani + MidKnight Server Running"
  );
});

app.get("/health", (req, res) => {

  res.send("ok");
});

app.get("/debug", (req, res) => {

  res.json({
    status: "ok",
    sessions:
      sessions.size,
    states:
      oauthStates.size
  });
});

// ====================== DANI OAUTH ======================

app.get(
  "/daniapp/oauth/start",
  (req, res) => {

    const pkce =
      createPkceState(
        "daniapp"
      );

    const authUrl =
      new URL(
        "https://auth.fanvue.com/oauth2/auth"
      );

    authUrl.searchParams.set(
      "response_type",
      "code"
    );

    authUrl.searchParams.set(
      "client_id",
      DANI_CLIENT_ID
    );

    authUrl.searchParams.set(
      "redirect_uri",
      DANI_REDIRECT_URI
    );

    authUrl.searchParams.set(
      "scope",
      "openid offline_access write:post write:media read:self"
    );

    authUrl.searchParams.set(
      "state",
      pkce.state
    );

    authUrl.searchParams.set(
      "code_challenge",
      pkce.codeChallenge
    );

    authUrl.searchParams.set(
      "code_challenge_method",
      "S256"
    );

    res.redirect(
      authUrl.toString()
    );
  }
);

app.get(
  "/daniapp/oauth/callback",
  async (req, res) => {

    try {

      const {
        code,
        state
      } = req.query;

      const st =
        oauthStates.get(
          state
        );

      if (!st) {

        return res
          .status(400)
          .send(
            "Invalid state"
          );
      }

      oauthStates.delete(
        state
      );

      const tokenData =
        await exchangeToken({
          clientId:
            DANI_CLIENT_ID,
          clientSecret:
            DANI_CLIENT_SECRET,
          redirectUri:
            DANI_REDIRECT_URI,
          code,
          codeVerifier:
            st.codeVerifier
        });

      const profile =
        await getProfile(
          tokenData.access_token
        );

      const sid =
        makeSession({
          app:
            "daniapp",
          accessToken:
            tokenData.access_token,
          profile
        });

      const name =
        encodeURIComponent(
          profile.displayName ||
          "Dani Richmond"
        );

      const handle =
        encodeURIComponent(
          `@${(
            profile.handle ||
            ""
          ).replace("@", "")}`
        );

      const avatar =
        encodeURIComponent(
          profile.avatarUrl ||
          ""
        );

      res.redirect(
        `${FRONTEND_ORIGIN}/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`
      );

    } catch (err) {

      console.error(err);

      res.status(500).send(
        "OAuth failed"
      );
    }
  }
);

// ====================== MIDKNIGHT VIP OAUTH ======================

app.get(
  "/midknight/oauth/start",
  (req, res) => {

    const pkce =
      createPkceState(
        "midknight"
      );

    const authUrl =
      new URL(
        "https://auth.fanvue.com/oauth2/auth"
      );

    authUrl.searchParams.set(
      "response_type",
      "code"
    );

    authUrl.searchParams.set(
      "client_id",
      MIDKNIGHT_CLIENT_ID
    );

    authUrl.searchParams.set(
      "redirect_uri",
      MIDKNIGHT_REDIRECT_URI
    );

    authUrl.searchParams.set(
      "scope",
      "openid offline_access write:post write:media read:self"
    );

    authUrl.searchParams.set(
      "state",
      pkce.state
    );

    authUrl.searchParams.set(
      "code_challenge",
      pkce.codeChallenge
    );

    authUrl.searchParams.set(
      "code_challenge_method",
      "S256"
    );

    res.redirect(
      authUrl.toString()
    );
  }
);

app.get(
  "/midknight/oauth/callback",
  async (req, res) => {

    try {

      const {
        code,
        state
      } = req.query;

      const st =
        oauthStates.get(
          state
        );

      if (!st) {

        return res
          .status(400)
          .send(
            "Invalid state"
          );
      }

      oauthStates.delete(
        state
      );

      const tokenData =
        await exchangeToken({
          clientId:
            MIDKNIGHT_CLIENT_ID,
          clientSecret:
            MIDKNIGHT_CLIENT_SECRET,
          redirectUri:
            MIDKNIGHT_REDIRECT_URI,
          code,
          codeVerifier:
            st.codeVerifier
        });

      const profile =
        await getProfile(
          tokenData.access_token
        );

      const sid =
        makeSession({
          app:
            "midknight",
          accessToken:
            tokenData.access_token,
          profile
        });

      res.redirect(
        `${FRONTEND_ORIGIN}/midknight-vip-services/?connected=1&sid=${sid}`
      );

    } catch (err) {

      console.error(err);

      res.status(500).send(
        "OAuth failed"
      );
    }
  }
);

// ====================== SINGLE POST ======================

app.post(
  "/daniapp/api/post",
  upload.single("media"),
  async (req, res) => {

    const session =
      getSession(req);

    if (
      !session?.accessToken
    ) {

      return res
        .status(401)
        .json({
          ok: false,
          error:
            "Fanvue not connected"
        });
    }

    if (!req.file) {

      return res
        .status(400)
        .json({
          ok: false,
          error:
            "No media file"
        });
    }

    try {

      const result =
        await uploadMediaAndCreatePost({
          accessToken:
            session.accessToken,
          file:
            req.file,
          caption:
            req.body.caption,
          audience:
            req.body.audience,
          price:
            req.body.price
        });

      res.json({
        ok: true,
        message:
          "Post published successfully.",
        result
      });

    } catch (err) {

      console.error(
        "Post error:",
        err?.response?.data ||
        err.message
      );

      res.status(500).json({
        ok: false,
        error:
          err?.response?.data ||
          err.message
      });
    }
  }
);

// ====================== BULK POST ======================

app.post(
  "/daniapp/api/bulk-post",
  upload.array("media", 50),
  async (req, res) => {

    const session =
      getSession(req);

    if (
      !session?.accessToken
    ) {

      return res
        .status(401)
        .json({
          ok: false,
          error:
            "Fanvue not connected"
        });
    }

    if (
      !req.files ||
      !req.files.length
    ) {

      return res
        .status(400)
        .json({
          ok: false,
          error:
            "No files uploaded"
        });
    }

    try {

      const results =
        await processBulkUploads({
          accessToken:
            session.accessToken,
          files:
            req.files,
          caption:
            req.body.caption,
          audience:
            req.body.audience,
          price:
            req.body.price
        });

      res.json({
        ok: true,
        total:
          results.length,
        success:
          results.filter(
            r => r.success
          ).length,
        failed:
          results.filter(
            r => !r.success
          ).length,
        results
      });

    } catch (err) {

      console.error(
        "Bulk upload error:",
        err
      );

      res.status(500).json({
        ok: false,
        error:
          err.message
      });
    }
  }
);

// ====================== LOGOUT ======================

app.post(
  "/daniapp/logout",
  (req, res) => {

    const sid =
      req.get(
        "x-dani-session"
      );

    if (sid) {
      sessions.delete(sid);
    }

    res.json({
      ok: true
    });
  }
);

app.listen(PORT, () => {

  console.log(
    "===================================================="
  );

  console.log(
    "🚀 DANI + MIDKNIGHT SERVER RUNNING"
  );

  console.log(
    `PORT: ${PORT}`
  );

  console.log(
    "===================================================="
  );
});
