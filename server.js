// server.cjs — Two-App Fanvue Server: MidKnight MVP + DaniApp

require("dotenv").config();

const express = require("express");
const axios = require("axios");
const crypto = require("crypto");
const path = require("path");
const cookieParser = require("cookie-parser");

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
const SESSION_SECRET = (process.env.SESSION_SECRET || "change-me").trim();
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

// RAW BODY
function rawBodySaver(req, res, buf) {
  if (buf && buf.length) req.rawBody = buf.toString("utf8");
}

// MIDDLEWARE
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

app.use(
  express.json({
    limit: "25mb",
    verify: rawBodySaver,
  })
);

app.use(express.urlencoded({ extended: true, limit: "25mb" }));
app.use(cookieParser(SESSION_SECRET));

// HELPERS
function baseUrl(req) {
  return `https://${req.get("host")}`;
}

function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return next();

  const got = (req.get("x-admin-token") || "").trim();

  if (got && got === ADMIN_TOKEN) return next();

  return res.status(401).json({ error: "Unauthorized" });
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

function addEvent(evt) {
  webhookEvents.unshift(evt);

  if (webhookEvents.length > MAX_EVENTS) {
    webhookEvents.length = MAX_EVENTS;
  }
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

  return {
    state,
    nonce,
    codeVerifier,
    codeChallenge,
  };
}

function verifyFanvueSignature(req) {
  if (!WEBHOOK_SECRET) {
    return {
      ok: true,
      reason: "WEBHOOK_SECRET not set",
    };
  }

  const sig = (req.get("
