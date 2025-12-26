const express = require("express");
const app = express();

app.use(express.json({ type: "*/*" }));

app.get("/health", (req, res) => {
  res.status(200).send("OK");
});

app.post("/webhooks/fanvue", (req, res) => {
  console.log("Fanvue webhook received", req.body);
  res.sendStatus(200);
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log("fanvue-proxy2 listening on", port);
});
