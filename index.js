const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

const BASE_URL = process.env.BASE_URL;
const X_CLIENT_ID = process.env.X_CLIENT_ID;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET;

const REDIRECT_URI = `${BASE_URL}/auth/x/callback`;

const sessions = new Map();

app.use(express.json());

function page(title, body) {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<style>
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Arial,sans-serif;
  background:#f4f7fb;
  color:#172033;
}
nav{
  background:#111827;
  padding:18px;
  text-align:center;
}
nav a{
  color:white;
  text-decoration:none;
  margin:0 12px;
}
.container{
  max-width:850px;
  margin:50px auto;
  padding:30px;
}
.card{
  background:white;
  padding:35px;
  border-radius:18px;
  box-shadow:0 8px 30px rgba(0,0,0,.08);
}
h1{margin-top:0}
button{
  border:0;
  padding:14px 24px;
  border-radius:10px;
  background:#111827;
  color:white;
  font-size:16px;
  cursor:pointer;
}
button:hover{opacity:.9}
footer{
  text-align:center;
  padding:30px;
  color:#667085;
}
</style>
</head>
<body>
<nav>
<a href="/">Home</a>
<a href="/privacy">Privacy</a>
<a href="/terms">Terms</a>
</nav>

<div class="container">
<div class="card">
${body}
</div>
</div>

<footer>X OAuth Application</footer>
</body>
</html>`;
}

app.get("/", (req, res) => {
  res.send(page("X OAuth App", `
    <h1>Connect with X</h1>
    <p>
      This application demonstrates secure X OAuth 2.0
      authorization using PKCE.
    </p>

    <a href="/auth/x">
      <button>Connect X Account</button>
    </a>
  `));
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "X OAuth Application"
  });
});

app.get("/auth/x", (req, res) => {
  if (!X_CLIENT_ID || !BASE_URL) {
    return res.status(500).send("Missing X_CLIENT_ID or BASE_URL");
  }

  const state = crypto.randomBytes(32).toString("hex");

  const verifier = crypto
    .randomBytes(32)
    .toString("base64url");

  const challenge = crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");

  sessions.set(state, {
    verifier,
    created: Date.now()
  });

  const params = new URLSearchParams({
    response_type: "code",
    client_id: X_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: "tweet.read users.read",
    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  res.redirect(
    `https://x.com/i/oauth2/authorize?${params.toString()}`
  );
});

app.get("/auth/x/callback", async (req, res) => {
  const { code, state, error, error_description } = req.query;

  if (error) {
    return res.status(400).send(
      page("X OAuth Error", `
        <h1>Authorization Failed</h1>
        <p>${error}</p>
        <p>${error_description || ""}</p>
        <a href="/">Return home</a>
      `)
    );
  }

  if (!code || !state) {
    return res.status(400).send(
      page("OAuth Error", `
        <h1>Missing authorization data</h1>
        <p>The authorization code or state was not provided.</p>
      `)
    );
  }

  const session = sessions.get(state);

  if (!session) {
    return res.status(400).send(
      page("OAuth Error", `
        <h1>Invalid or expired state</h1>
        <p>Please start the X authorization process again.</p>
      `)
    );
  }

  sessions.delete(state);

  try {
    const credentials =
      Buffer.from(
        `${X_CLIENT_ID}:${X_CLIENT_SECRET}`
      ).toString("base64");

    const response = await fetch(
      "https://api.x.com/2/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded",
          "Authorization":
            `Basic ${credentials}`
        },
        body: new URLSearchParams({
          code,
          grant_type: "authorization_code",
          redirect_uri: REDIRECT_URI,
          code_verifier: session.verifier
        })
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).send(
        page("Token Error", `
          <h1>Token Exchange Failed</h1>
          <pre>${JSON.stringify(data, null, 2)}</pre>
        `)
      );
    }

    res.send(
      page("Authorization Successful", `
        <h1>✓ X Authorization Successful</h1>

        <p>Your application successfully received
        an OAuth 2.0 access token.</p>

        <p>
        <strong>Token type:</strong>
        ${data.token_type || "Bearer"}
        </p>

        <p>
        <strong>Expires in:</strong>
        ${data.expires_in || "N/A"} seconds
        </p>

        <p>
        <strong>Scope:</strong>
        ${data.scope || "N/A"}
        </p>

        <p>
        The access token is intentionally not displayed
        on this page.
        </p>
      `)
    );

    console.log("OAuth token received successfully.");

  } catch (err) {
    console.error(err);

    res.status(500).send(
      page("Server Error", `
        <h1>Server Error</h1>
        <p>Unable to contact X's OAuth service.</p>
      `)
    );
  }
});

app.get("/privacy", (req, res) => {
  res.send(page("Privacy Policy", `
    <h1>Privacy Policy</h1>

    <p>
      This application uses X OAuth 2.0 to authenticate
      users who choose to connect their X account.
    </p>

    <p>
      Authentication information is used only to provide
      the functionality requested by the user.
    </p>

    <p>
      We do not sell personal information.
    </p>

    <p>
      Users may revoke the application's access through
      their X account settings.
    </p>
  `));
});

app.get("/terms", (req, res) => {
  res.send(page("Terms of Service", `
    <h1>Terms of Service</h1>

    <p>
      By using this application, you agree to use it
      lawfully and only with accounts you are authorized
      to access.
    </p>

    <p>
      The application is provided for legitimate
      authentication and development purposes.
    </p>

    <p>
      Users are responsible for complying with X's
      applicable terms and developer policies.
    </p>
  `));
});

app.listen(PORT, () => {
  console.log("X OAuth server running");
  console.log(`Port: ${PORT}`);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Callback: ${REDIRECT_URI}`);
});
