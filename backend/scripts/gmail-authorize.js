// One-time Gmail API sender authorization for hosts that block SMTP (Render Free).
// Opens Google's consent page, captures the refresh token on a local loopback
// address, stores it in the private .env (never printed), then sends a test
// email to MAIL_FROM through the Gmail API to prove delivery works.
//
// Prerequisites in Google Cloud Console (same project as the OAuth client):
//   - Gmail API enabled
//   - Authorized redirect URI on the OAuth client: http://127.0.0.1:53682/oauth2callback
//   - OAuth consent screen "In production" (Testing tokens expire after 7 days)
//
// Usage: node backend/scripts/gmail-authorize.js
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");
const envPath = path.join(__dirname, "../../.env");
require("dotenv").config({ path: envPath, quiet: true });

const PORT = 53682;
const REDIRECT = `http://127.0.0.1:${PORT}/oauth2callback`;
const clientId = process.env.GMAIL_CLIENT_ID || process.env.GOOGLE_OAUTH_CLIENT_ID;
const clientSecret = process.env.GMAIL_CLIENT_SECRET || process.env.GOOGLE_OAUTH_CLIENT_SECRET;
const sender = process.env.MAIL_FROM;
if (!clientId || !clientSecret || !sender) {
  console.error("FIX: .env needs MAIL_FROM and either GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET or GOOGLE_OAUTH_CLIENT_ID/GOOGLE_OAUTH_CLIENT_SECRET.");
  process.exit(1);
}

function setEnv(updates) {
  let text = fs.readFileSync(envPath, "utf8");
  const eol = text.includes("\r\n") ? "\r\n" : "\n";
  for (const [key, value] of Object.entries(updates)) {
    const line = `${key}=${value}`;
    const pattern = new RegExp(`^${key}=.*$`, "m");
    text = pattern.test(text) ? text.replace(pattern, line) : text.replace(/\s*$/, "") + eol + line + eol;
  }
  fs.writeFileSync(envPath, text);
}

const state = crypto.randomBytes(16).toString("hex");
const authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" + new URLSearchParams({
  client_id: clientId,
  redirect_uri: REDIRECT,
  response_type: "code",
  scope: "https://www.googleapis.com/auth/gmail.send",
  access_type: "offline",
  prompt: "consent",
  login_hint: sender,
  state,
});

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, REDIRECT);
  if (url.pathname !== "/oauth2callback") { res.writeHead(404).end(); return; }
  const finish = (ok, text) => {
    res.writeHead(ok ? 200 : 400, { "content-type": "text/plain; charset=utf-8" }).end(text);
    server.close();
  };
  if (url.searchParams.get("state") !== state) return finish(false, "State mismatch. Close this tab and run the script again.");
  if (url.searchParams.get("error")) {
    console.error("FAILED: Google returned", url.searchParams.get("error"));
    process.exitCode = 1;
    return finish(false, "Authorization was not granted. You can close this tab.");
  }
  try {
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        code: url.searchParams.get("code"), client_id: clientId, client_secret: clientSecret,
        redirect_uri: REDIRECT, grant_type: "authorization_code",
      }),
    });
    const token = await tokenResponse.json();
    if (!tokenResponse.ok || !token.refresh_token) {
      console.error("FAILED: token exchange:", token.error || tokenResponse.status, token.error_description || "(no refresh token returned)");
      process.exitCode = 1;
      return finish(false, "Token exchange failed. See the terminal. You can close this tab.");
    }
    setEnv({ GMAIL_CLIENT_ID: clientId, GMAIL_CLIENT_SECRET: clientSecret, GMAIL_REFRESH_TOKEN: token.refresh_token });
    console.log("SAVED: GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET and GMAIL_REFRESH_TOKEN written to .env (values not printed).");
    const { createMailer } = require("../src/lib/mailer");
    const mail = createMailer({ ...process.env, MAIL_DELIVERY: "gmail-api", GMAIL_CLIENT_ID: clientId, GMAIL_CLIENT_SECRET: clientSecret, GMAIL_REFRESH_TOKEN: token.refresh_token });
    await mail({ to: sender, subject: "HOPE Gmail API sender check", text: "If you can read this, HOPE can send email through the Gmail API." });
    console.log(`SENT: test email delivered to ${sender} through the Gmail API.`);
    finish(true, "Done. HOPE is authorized to send email. You can close this tab.");
  } catch (error) {
    console.error("FAILED:", error.message);
    process.exitCode = 1;
    finish(false, "Something failed. See the terminal. You can close this tab.");
  }
});
server.listen(PORT, "127.0.0.1", () => {
  console.log("Opening Google consent page. Sign in as", sender, "and allow \"Send email on your behalf\".");
  console.log("If the browser does not open, visit:\n" + authUrl);
  if (process.platform === "win32") execFile("rundll32", ["url.dll,FileProtocolHandler", authUrl]);
  else execFile(process.platform === "darwin" ? "open" : "xdg-open", [authUrl]);
});
setTimeout(() => { console.error("TIMEOUT: no response from Google within 10 minutes."); process.exit(1); }, 600000).unref();
