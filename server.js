const express = require("express");
const app = express();

app.use(express.json({ type: "*/*" }));

// in-memory store (last 200)
const events = [];

app.get("/health", (req, res) => res.status(200).send("OK"));

// Fanvue webhook (POST)
app.post("/webhooks/fanvue", (req, res) => {
  const evt = {
    ts: new Date().toISOString(),
    headers: req.headers,
    body: req.body
  };
  events.unshift(evt);
  if (events.length > 200) events.pop();
  console.log("Fanvue webhook received", evt.ts);
  res.sendStatus(200);
});

// Dashboard can read recent events (GET) with token
app.get("/events", (req, res) => {
  const token = req.query.token || req.get("x-admin-token");
  if (process.env.ADMIN_TOKEN && token !== process.env.ADMIN_TOKEN) {
    return res.sendStatus(401);
  }
  res.json({ count: events.length, events });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log("listening on", port));
