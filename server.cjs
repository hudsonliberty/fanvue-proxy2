require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

const DANI_CLIENT_ID = process.env.DANI_CLIENT_ID || "";
const DANI_CLIENT_SECRET = process.env.DANI_CLIENT_SECRET || "";
const DANI_REDIRECT_URI = process.env.DANI_REDIRECT_URI || "";

const sessions = new Map();
const oauthStates = new Map();

function createPkce() {
  const state = crypto.randomBytes(16).toString("hex");

  const verifier = crypto.randomBytes(32).toString("hex");

  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  oauthStates.set(state, {
    verifier,
    created: Date.now(),
  });

  return {
    state,
    verifier,
    challenge,
  };
}

console.log("============================================================");
console.log("ON MY TIME FANVUE SERVICE STARTING");
console.log("DANI_CLIENT_ID present:", !!DANI_CLIENT_ID);
console.log("DANI_CLIENT_SECRET present:", !!DANI_CLIENT_SECRET);
console.log("DANI_REDIRECT_URI present:", !!DANI_REDIRECT_URI);
console.log("PORT:", PORT);
console.log("============================================================");

app.get("/", (req, res) => {
  res.send(`
    <html>
      <body style="background:#111;color:#fff;font-family:sans-serif;padding:40px;">
        <h1>Fanvue Proxy Running</h1>
        <p>Dani OAuth:</p>
        <a href="/daniapp/oauth/start">Connect Fanvue</a>
      </body>
    </html>
  `);
});

app.get("/env-check", (req, res) => {
  res.json({
    ok: true,
    server: "fanvue-proxy2",
    app: "two-app-server",
    time: new Date().toISOString(),
    env: {
      DANI_CLIENT_ID: !!DANI_CLIENT_ID,
      DANI_CLIENT_SECRET: !!DANI_CLIENT_SECRET,
      DANI_REDIRECT_URI: DANI_REDIRECT_URI,
    },
    sessions: sessions.size,
    states: oauthStates.size,
  });
});

app.get("/daniapp/oauth/start", (req, res) => {
  try {
    const pkce = createPkce();

    const authUrl = new URL(
      "https://auth.fanvue.com/oauth2/auth"
    );

    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", DANI_CLIENT_ID);
    authUrl.searchParams.set(
      "redirect_uri",
      DANI_REDIRECT_URI
    );

    authUrl.searchParams.set(
      "scope",
      "openid offline_access write:post write:media"
    );

    authUrl.searchParams.set("state", pkce.state);

    authUrl.searchParams.set(
      "code_challenge",
      pkce.challenge
    );

    authUrl.searchParams.set(
      "code_challenge_method",
      "S256"
    );

    return res.redirect(authUrl.toString());
  } catch (err) {
    console.error(err);
    return res.status(500).send("OAuth start failed");
  }
});

app.get("/daniapp/oauth/callback", async (req, res) => {
  try {
    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send("Missing code/state");
    }

    const stored = oauthStates.get(state);

    if (!stored) {
      return res.status(400).send("Expired state");
    }

    oauthStates.delete(state);

    const basicAuth = Buffer.from(
      `${DANI_CLIENT_ID}:${DANI_CLIENT_SECRET}`
    ).toString("base64");

    const tokenResp = await axios.post(
      "https://auth.fanvue.com/oauth2/token",
      new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: DANI_REDIRECT_URI,
        code_verifier: stored.verifier,
      }).toString(),
      {
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
          Authorization: `Basic ${basicAuth}`,
        },
        timeout: 30000,
      }
    );

    const accessToken =
      tokenResp.data.access_token;

    if (!accessToken) {
      throw new Error("No access token");
    }

    let profile = {};

    try {
      const me = await axios.get(
        "https://api.fanvue.com/users/me",
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
            "X-Fanvue-API-Version": "2025-06-26",
          },
        }
      );

      profile = me.data || {};
    } catch (e) {
      console.log("Profile fetch skipped");
    }

    const sid = crypto
      .randomBytes(24)
      .toString("hex");

    sessions.set(sid, {
      accessToken,
      profile,
      created: Date.now(),
    });

    console.log("SESSION CREATED:", sid);

    const name =
      encodeURIComponent(
        profile.displayName || "Creator"
      );

    const handle =
      encodeURIComponent(
        profile.handle || "@creator"
      );

    const avatar =
      encodeURIComponent(
        profile.avatarUrl || ""
      );

    return res.redirect(
      `https://thesuccessmindset.club/daniapp/index.html?connected=1&sid=${sid}&name=${name}&handle=${handle}&avatar=${avatar}`
    );
  } catch (err) {
    console.error("CALLBACK ERROR");

    console.error(
      err?.response?.status
    );

    console.error(
      err?.response?.data || err.message
    );

    return res
      .status(500)
      .send("OAuth callback failed");
  }
});

app.get("/daniapp/debug/full", (req, res) => {
  const sid =
    req.query.sid ||
    req.get("x-dani-session");

  const session = sid
    ? sessions.get(sid)
    : null;

  res.json({
    ok: true,
    sidPresent: !!sid,
    sid,
    sessionExists: !!session,
    sessions: sessions.size,
    profile: session?.profile || null,
  });
});

app.post("/daniapp/api/post", async (req, res) => {
  try {
    const sid =
      req.get("x-dani-session");

    if (!sid) {
      return res.status(401).json({
        ok: false,
        error: "Missing session id",
      });
    }

    const session =
      sessions.get(sid);

    if (!session) {
      return res.status(401).json({
        ok: false,
        error: "Fanvue is not connected",
      });
    }

    return res.json({
      ok: true,
      message: "CONNECTED",
      profile: session.profile || null,
    });
  } catch (err) {
    console.error(err);

    return res.status(500).json({
      ok: false,
      error: err.message,
    });
  }
});

app.post("/daniapp/api/bulk-post", async (req, res) => {
  return res.json({
    ok: true,
    message: "Bulk endpoint ready",
  });
});

app.listen(PORT, () => {
  console.log("============================================================");
  console.log("SERVER READY");
  console.log("Dani OAuth: https://fanvue-proxy2.onrender.com/daniapp/oauth/start");
  console.log("Env Check: https://fanvue-proxy2.onrender.com/env-check");
  console.log("Dani Debug: https://fanvue-proxy2.onrender.com/daniapp/debug/full");
  console.log("============================================================");
});
