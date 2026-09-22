const express = require("express");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 10000;
const BASE_URL = process.env.BASE_URL || "https://xauth-v52j.onrender.com";

const X_CLIENT_ID = process.env.X_CLIENT_ID;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET;

const REDIRECT_URI = `${BASE_URL}/auth/x/callback`;

const sessions = new Map();

app.use(express.json());

function escapeHtml(value = "") {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function page(title, body) {
  return `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${escapeHtml(title)}</title>

<style>
* {
  box-sizing: border-box;
}

body {
  margin: 0;
  font-family: Arial, sans-serif;
  background: #f5f7fa;
  color: #111827;
}

nav {
  background: #000;
  padding: 18px;
  text-align: center;
}

nav a {
  color: white;
  text-decoration: none;
  margin: 0 15px;
  font-weight: bold;
}

.container {
  max-width: 850px;
  margin: 45px auto;
  padding: 25px;
}

.card {
  background: white;
  padding: 30px;
  border-radius: 14px;
  box-shadow: 0 5px 25px rgba(0,0,0,0.08);
}

h1 {
  margin-top: 0;
}

button,
.connect {
  display: inline-block;
  background: #000;
  color: white;
  border: none;
  padding: 13px 20px;
  border-radius: 8px;
  cursor: pointer;
  text-decoration: none;
  font-size: 15px;
  margin: 5px;
}

button:hover,
.connect:hover {
  opacity: 0.8;
}

textarea {
  width: 100%;
  min-height: 150px;
  padding: 14px;
  border: 1px solid #ccc;
  border-radius: 8px;
  font-family: monospace;
  font-size: 14px;
  resize: vertical;
}

.info {
  background: #f1f5f9;
  padding: 15px;
  border-radius: 8px;
  margin: 15px 0;
}

.warning {
  background: #fff7ed;
  border-left: 4px solid #f97316;
  padding: 15px;
  margin-top: 20px;
}

.success {
  color: #15803d;
  font-weight: bold;
}

.error {
  color: #dc2626;
  font-weight: bold;
}

footer {
  text-align: center;
  padding: 30px;
  color: #666;
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

<footer>
  X OAuth Application
</footer>

</body>
</html>
`;
}

/* HOME */

app.get("/", (req, res) => {
  res.send(
    page(
      "X OAuth Application",
      `
      <h1>X OAuth 2.0 Application</h1>

      <p>
        Connect your X account using OAuth 2.0 authorization.
      </p>

      <a class="connect" href="/auth/x">
        Connect with X
      </a>
      `
    )
  );
});

/* HEALTH */

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "X OAuth Application",
    redirect_uri: REDIRECT_URI
  });
});

/* START OAUTH */

app.get("/auth/x", async (req, res) => {
  try {
    if (!X_CLIENT_ID) {
      return res.status(500).send(
        page(
          "Configuration Error",
          `
          <h1>Configuration Error</h1>
          <p class="error">X_CLIENT_ID is not configured.</p>
          `
        )
      );
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
      createdAt: Date.now()
    });

    const params = new URLSearchParams({
      response_type: "code",
      client_id: X_CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: "users.read tweet.read",
      state,
      code_challenge: challenge,
      code_challenge_method: "S256"
    });

    const authorizationUrl =
      `https://x.com/i/oauth2/authorize?${params.toString()}`;

    res.redirect(authorizationUrl);

  } catch (error) {
    console.error(error);

    res.status(500).send(
      page(
        "OAuth Error",
        `
        <h1>OAuth Error</h1>
        <p class="error">${escapeHtml(error.message)}</p>
        `
      )
    );
  }
});

/* OAUTH CALLBACK */

app.get("/auth/x/callback", async (req, res) => {
  try {
    const {
      code,
      state,
      error,
      error_description
    } = req.query;

    /* X returned an OAuth error */

    if (error) {
      return res.status(400).send(
        page(
          "X Authorization Error",
          `
          <h1>X Authorization Failed</h1>

          <p class="error">
            ${escapeHtml(error)}
          </p>

          <div class="info">
            ${escapeHtml(error_description || "No additional information provided.")}
          </div>

          <a class="connect" href="/auth/x">
            Try Again
          </a>
          `
        )
      );
    }

    /* Validate state */

    if (!state || !sessions.has(state)) {
      return res.status(400).send(
        page(
          "Invalid State",
          `
          <h1>Invalid OAuth State</h1>

          <p class="error">
            The OAuth state is missing, expired, or invalid.
          </p>

          <a class="connect" href="/auth/x">
            Start Again
          </a>
          `
        )
      );
    }

    const session = sessions.get(state);
    sessions.delete(state);

    if (!code) {
      return res.status(400).send(
        page(
          "Missing Code",
          `
          <h1>Authorization Code Missing</h1>

          <p class="error">
            X did not return an authorization code.
          </p>
          `
        )
      );
    }

    /*
      Exchange authorization code for access token.
    */

    const tokenBody = new URLSearchParams({
      code,
      grant_type: "authorization_code",
      redirect_uri: REDIRECT_URI,
      code_verifier: session.verifier
    });

    const headers = {
      "Content-Type": "application/x-www-form-urlencoded"
    };

    /*
      Confidential clients use HTTP Basic authentication.
      Public clients send client_id in the request body.
    */

    if (X_CLIENT_SECRET) {
      const basicAuth = Buffer
        .from(`${X_CLIENT_ID}:${X_CLIENT_SECRET}`)
        .toString("base64");

      headers.Authorization = `Basic ${basicAuth}`;
    } else {
      tokenBody.set("client_id", X_CLIENT_ID);
    }

    console.log("Exchanging OAuth authorization code...");

    const response = await fetch(
      "https://api.x.com/2/oauth2/token",
      {
        method: "POST",
        headers,
        body: tokenBody
      }
    );

    const raw = await response.text();

    let data;

    try {
      data = JSON.parse(raw);
    } catch {
      data = {
        raw_response: raw
      };
    }

    console.log("X token response status:", response.status);

    if (!response.ok) {
      console.error("X token exchange failed:", data);

      return res.status(500).send(
        page(
          "Token Exchange Failed",
          `
          <h1>Token Exchange Failed</h1>

          <p class="error">
            X returned HTTP ${response.status}
          </p>

          <div class="info">
            <pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>
          </div>

          <a class="connect" href="/auth/x">
            Try Again
          </a>
          `
        )
      );
    }

    if (!data.access_token) {
      return res.status(500).send(
        page(
          "Access Token Missing",
          `
          <h1>Access Token Missing</h1>

          <p class="error">
            X returned a successful response, but no access token was found.
          </p>

          <div class="info">
            <pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre>
          </div>
          `
        )
      );
    }

    const accessToken = data.access_token;
    const tokenType = data.token_type || "bearer";
    const expiresIn = data.expires_in || "Not provided";
    const scope = data.scope || "Not provided";

    /*
      SUCCESS PAGE
      The access token is intentionally displayed here
      because this application is being used for demonstration/testing.
    */

    res.send(
      page(
        "OAuth Success",
        `
        <h1 class="success">
          ✓ X Authorization Successful
        </h1>

        <p>
          Your application successfully received an
          OAuth 2.0 access token.
        </p>

        <div class="info">
          <strong>Token type:</strong>
          ${escapeHtml(tokenType)}
        </div>

        <div class="info">
          <strong>Expires in:</strong>
          ${escapeHtml(String(expiresIn))} seconds
        </div>

        <div class="info">
          <strong>Scope:</strong>
          ${escapeHtml(scope)}
        </div>

        <h2>Access Token</h2>

        <textarea id="accessToken" spellcheck="false">${escapeHtml(accessToken)}</textarea>

        <div>
          <button onclick="copyToken()">
            Copy Access Token
          </button>

          <button onclick="selectToken()">
            Select Token
          </button>
        </div>

        <p id="copyStatus"></p>

        <div class="warning">
          <strong>Security warning:</strong><br>
          This is a live OAuth access token. Do not publish it,
          commit it to GitHub, or share it publicly. Revoke or
          regenerate the token after your demonstration.
        </div>

        <br>

        <a class="connect" href="/">
          Back Home
        </a>

        <script>
        function copyToken() {
          const token = document.getElementById("accessToken").value;

          navigator.clipboard.writeText(token)
            .then(() => {
              document.getElementById("copyStatus").textContent =
                "✓ Access token copied to clipboard.";
            })
            .catch(() => {
              document.getElementById("copyStatus").textContent =
                "Copy failed. Use Select Token instead.";
            });
        }

        function selectToken() {
          const textarea = document.getElementById("accessToken");

          textarea.focus();
          textarea.select();

          document.getElementById("copyStatus").textContent =
            "Token selected. You can copy it manually.";
        }
        </script>
        `
      )
    );

  } catch (error) {
    console.error("OAuth callback error:", error);

    res.status(500).send(
      page(
        "Server Error",
        `
        <h1>Server Error</h1>

        <p class="error">
          ${escapeHtml(error.message)}
        </p>

        <a class="connect" href="/auth/x">
          Try Again
        </a>
        `
      )
    );
  }
});

/* PRIVACY */

app.get("/privacy", (req, res) => {
  res.send(
    page(
      "Privacy Policy",
      `
      <h1>Privacy Policy</h1>

      <p>
        This demonstration application uses X OAuth 2.0
        to authenticate users and obtain authorization tokens.
      </p>

      <p>
        The application does not intentionally sell or distribute
        user information.
      </p>

      <p>
        OAuth tokens should be treated as confidential credentials
        and should not be shared publicly.
      </p>
      `
    )
  );
});

/* TERMS */

app.get("/terms", (req, res) => {
  res.send(
    page(
      "Terms of Service",
      `
      <h1>Terms of Service</h1>

      <p>
        This website is a demonstration application for
        testing X OAuth 2.0 authorization.
      </p>

      <p>
        By using this application, you authorize the application
        to request only the permissions presented during the
        X authorization process.
      </p>

      <p>
        Users are responsible for protecting any OAuth access
        tokens displayed by the application.
      </p>
      `
    )
  );
});

/* START SERVER */

app.listen(PORT, () => {
  console.log("====================================");
  console.log("X OAuth Application");
  console.log("Server running on port:", PORT);
  console.log("Base URL:", BASE_URL);
  console.log("Redirect URI:", REDIRECT_URI);
  console.log("====================================");
});
