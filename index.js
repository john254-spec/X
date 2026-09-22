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

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function page(title, body) {
  return `
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title>

<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Arial, sans-serif;
  background: #f4f7fb;
  color: #172033;
}

nav {
  background: #111827;
  padding: 18px;
  text-align: center;
}

nav a {
  color: white;
  text-decoration: none;
  margin: 0 12px;
  font-weight: bold;
}

nav a:hover {
  text-decoration: underline;
}

.container {
  max-width: 900px;
  margin: 40px auto;
  padding: 20px;
}

.card {
  background: white;
  padding: 35px;
  border-radius: 18px;
  box-shadow: 0 8px 30px rgba(0,0,0,.08);
}

h1 {
  margin-top: 0;
}

button {
  border: 0;
  padding: 14px 24px;
  border-radius: 10px;
  background: #111827;
  color: white;
  font-size: 16px;
  cursor: pointer;
  margin-top: 10px;
}

button:hover {
  opacity: .9;
}

textarea {
  width: 100%;
  min-height: 150px;
  padding: 14px;
  border: 1px solid #d0d5dd;
  border-radius: 10px;
  font-family: monospace;
  font-size: 13px;
  resize: vertical;
}

.info {
  background: #f8fafc;
  border-radius: 10px;
  padding: 15px;
  margin: 15px 0;
}

.warning {
  background: #fff7ed;
  border: 1px solid #fed7aa;
  border-radius: 10px;
  padding: 15px;
  margin: 20px 0;
}

.success {
  background: #ecfdf3;
  border: 1px solid #a7f3d0;
  border-radius: 10px;
  padding: 15px;
  margin-bottom: 20px;
}

pre {
  white-space: pre-wrap;
  word-break: break-word;
  background: #111827;
  color: #fff;
  padding: 15px;
  border-radius: 10px;
  overflow-x: auto;
}

footer {
  text-align: center;
  padding: 30px;
  color: #667085;
}
</style>
</head>

<body>

<nav>
  <a href="/">Home</a>
  <a href="/privacy">Privacy</a>
  <a href="/terms">Terms</a>
  <a href="/health">Health</a>
</nav>

<div class="container">
  <div class="card">
    ${body}
  </div>
</div>

<footer>
  X OAuth 2.0 Application
</footer>

</body>
</html>`;
}


/* =========================
   HOME
========================= */

app.get("/", (req, res) => {
  res.send(page("X OAuth App", `
    <h1>Connect with X</h1>

    <p>
      This application demonstrates X OAuth 2.0
      authorization using PKCE.
    </p>

    <div class="info">
      <strong>Base URL:</strong><br>
      ${escapeHtml(BASE_URL || "Not configured")}
    </div>

    <div class="info">
      <strong>Callback URL:</strong><br>
      ${escapeHtml(REDIRECT_URI)}
    </div>

    <a href="/auth/x">
      <button>Connect X Account</button>
    </a>
  `));
});


/* =========================
   HEALTH
========================= */

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "X OAuth Application",
    base_url: BASE_URL,
    callback: REDIRECT_URI
  });
});


/* =========================
   START X OAUTH
========================= */

app.get("/auth/x", (req, res) => {

  if (!X_CLIENT_ID || !BASE_URL) {
    return res.status(500).send(
      page("Configuration Error", `
        <h1>Configuration Error</h1>

        <p>
          Missing <strong>X_CLIENT_ID</strong>
          or <strong>BASE_URL</strong>.
        </p>
      `)
    );
  }

  const state = crypto
    .randomBytes(32)
    .toString("hex");

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

  /*
    Remove sessions older than 10 minutes.
  */

  for (const [key, value] of sessions.entries()) {
    if (Date.now() - value.created > 10 * 60 * 1000) {
      sessions.delete(key);
    }
  }

  const params = new URLSearchParams({
    response_type: "code",
    client_id: X_CLIENT_ID,
    redirect_uri: REDIRECT_URI,

    /*
      Read-only scopes for this demonstration.
    */
    scope: "tweet.read users.read",

    state,
    code_challenge: challenge,
    code_challenge_method: "S256"
  });

  const authorizationUrl =
    `https://x.com/i/oauth2/authorize?${params.toString()}`;

  res.redirect(authorizationUrl);
});


/* =========================
   OAUTH CALLBACK
========================= */

app.get("/auth/x/callback", async (req, res) => {

  const {
    code,
    state,
    error,
    error_description
  } = req.query;


  /* X returned an error */

  if (error) {

    return res.status(400).send(
      page("X OAuth Error", `
        <h1>Authorization Failed</h1>

        <div class="warning">
          <strong>Error:</strong>
          ${escapeHtml(error)}

          <br><br>

          <strong>Description:</strong>
          ${escapeHtml(error_description || "No description provided")}
        </div>

        <a href="/">
          <button>Return Home</button>
        </a>
      `)
    );
  }


  /* Missing OAuth data */

  if (!code || !state) {

    return res.status(400).send(
      page("OAuth Error", `
        <h1>Missing Authorization Data</h1>

        <p>
          The authorization code or state parameter
          was not provided by X.
        </p>

        <a href="/">
          <button>Return Home</button>
        </a>
      `)
    );
  }


  /* Verify state */

  const session = sessions.get(state);

  if (!session) {

    return res.status(400).send(
      page("OAuth Error", `
        <h1>Invalid or Expired State</h1>

        <p>
          The OAuth session has expired or is invalid.
          Please start the authorization process again.
        </p>

        <a href="/auth/x">
          <button>Try Again</button>
        </a>
      `)
    );
  }

  sessions.delete(state);


  try {

    if (!X_CLIENT_SECRET) {

      return res.status(500).send(
        page("Configuration Error", `
          <h1>Missing Client Secret</h1>

          <p>
            The <strong>X_CLIENT_SECRET</strong>
            environment variable is not configured.
          </p>
        `)
      );
    }


    /*
      X OAuth 2.0 token exchange
    */

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


    /*
      Token exchange failed
    */

    if (!response.ok) {

      console.error(
        "X token exchange failed:",
        data
      );

      return res.status(response.status).send(
        page("Token Error", `
          <h1>Token Exchange Failed</h1>

          <pre>${escapeHtml(
            JSON.stringify(data, null, 2)
          )}</pre>

          <a href="/">
            <button>Return Home</button>
          </a>
        `)
      );
    }


    /*
      SUCCESS
      Display OAuth access token.

      This is intentionally shown because
      this version is being used for a
      development/tutor demonstration.
    */

    const accessToken =
      data.access_token || "";

    const tokenType =
      data.token_type || "Bearer";

    const expiresIn =
      data.expires_in || "N/A";

    const scope =
      data.scope || "N/A";


    console.log(
      "OAuth token received successfully."
    );


    res.send(
      page("Authorization Successful", `

        <div class="success">

          <h1>✓ X Authorization Successful</h1>

          <p>
            Your X OAuth 2.0 authorization was
            completed successfully.
          </p>

        </div>


        <h2>Access Token</h2>

        <textarea
          id="accessToken"
          spellcheck="false"
          autocomplete="off"
        >${escapeHtml(accessToken)}</textarea>


        <button onclick="copyToken()">
          Copy Access Token
        </button>


        <button
          onclick="selectToken()"
        >
          Select Token
        </button>


        <div class="info">

          <p>
            <strong>Token Type:</strong>
            ${escapeHtml(tokenType)}
          </p>

          <p>
            <strong>Expires In:</strong>
            ${escapeHtml(expiresIn)}
            seconds
          </p>

          <p>
            <strong>Scope:</strong>
            ${escapeHtml(scope)}
          </p>

        </div>


        <div class="warning">

          <strong>Security warning:</strong>

          <p>
            This is a live OAuth credential.
            Do not publish it, commit it to GitHub,
            or send it to another person.
          </p>

          <p>
            This page is displaying it because
            this application is being used for
            development/testing.
          </p>

        </div>


        <script>

          function copyToken() {

            const token =
              document.getElementById(
                "accessToken"
              ).value;

            navigator.clipboard.writeText(token)
              .then(() => {
                alert(
                  "Access token copied to clipboard."
                );
              })
              .catch(() => {

                const textarea =
                  document.getElementById(
                    "accessToken"
                  );

                textarea.select();

                document.execCommand("copy");

                alert(
                  "Access token copied."
                );
              });
          }


          function selectToken() {

            const textarea =
              document.getElementById(
                "accessToken"
              );

            textarea.focus();
            textarea.select();
          }

        </script>

      `)
    );


  } catch (err) {

    console.error(
      "OAuth callback error:",
      err
    );

    res.status(500).send(
      page("Server Error", `

        <h1>Server Error</h1>

        <p>
          Unable to contact X's OAuth service.
        </p>

        <pre>${escapeHtml(
          err.message
        )}</pre>

        <a href="/">
          <button>Return Home</button>
        </a>

      `)
    );
  }
});


/* =========================
   PRIVACY POLICY
========================= */

app.get("/privacy", (req, res) => {

  res.send(
    page("Privacy Policy", `

      <h1>Privacy Policy</h1>

      <p>
        This application uses X OAuth 2.0 to
        authenticate users who choose to connect
        their X account.
      </p>

      <p>
        The application requests only the
        permissions necessary for its functionality.
      </p>

      <p>
        Authentication information is used only
        for the functionality requested by the user.
      </p>

      <p>
        We do not sell personal information.
      </p>

      <p>
        Users may revoke the application's access
        through their X account settings.
      </p>

      <p>
        Users should not share OAuth access tokens
        with other people.
      </p>

    `)
  );
});


/* =========================
   TERMS OF SERVICE
========================= */

app.get("/terms", (req, res) => {

  res.send(
    page("Terms of Service", `

      <h1>Terms of Service</h1>

      <p>
        By using this application, you agree to use
        it lawfully and only with accounts you are
        authorized to access.
      </p>

      <p>
        The application is provided for legitimate
        authentication and development purposes.
      </p>

      <p>
        Users are responsible for complying with
        X's applicable terms, policies and developer
        requirements.
      </p>

      <p>
        Users must not use this application to
        obtain unauthorized access to another person's
        account.
      </p>

    `)
  );
});


/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {

  console.log("");
  console.log("================================");
  console.log("X OAuth 2.0 Application");
  console.log("================================");

  console.log(
    `Port: ${PORT}`
  );

  console.log(
    `Base URL: ${BASE_URL}`
  );

  console.log(
    `Callback: ${REDIRECT_URI}`
  );

  console.log(
    "OAuth 2.0 PKCE: ENABLED"
  );

  console.log(
    "================================"
  );

});

After deploying this version to Render, start the flow at:

https://xauth-v52j.onrender.com/auth/x

After X authorization, the callback page will show the access token, token type, expiration time, and scopes, with buttons to select or copy the token.

Important: don't commit an actual access token to GitHub or paste one into this chat. If the displayed token is exposed, revoke it and authorize again.
