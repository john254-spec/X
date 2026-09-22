const express = require("express");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 10000;

const BASE_URL = process.env.BASE_URL;
const X_CLIENT_ID = process.env.X_CLIENT_ID;
const X_CLIENT_SECRET = process.env.X_CLIENT_SECRET;

const REDIRECT_URI =
  `${BASE_URL}/auth/x/callback`;

const sessions = new Map();

app.use(express.json());

/* ================================
   HTML ESCAPING
================================ */

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}


/* ================================
   PAGE TEMPLATE
================================ */

function page(title, body) {
  return `
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

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
  margin: 0 10px;
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
  box-shadow:
    0 8px 30px rgba(0,0,0,.08);
}

h1 {
  margin-top: 0;
}

h2 {
  margin-top: 30px;
}

button {
  border: 0;
  padding: 14px 22px;
  border-radius: 10px;
  background: #111827;
  color: white;
  font-size: 16px;
  cursor: pointer;
  margin: 6px 5px 6px 0;
}

button:hover {
  opacity: .9;
}

textarea {
  width: 100%;
  min-height: 180px;
  padding: 14px;
  border: 1px solid #d0d5dd;
  border-radius: 10px;
  font-family: monospace;
  font-size: 13px;
  resize: vertical;
  background: #fafafa;
}

.info {
  background: #f8fafc;
  border-radius: 10px;
  padding: 16px;
  margin: 18px 0;
}

.success {
  background: #ecfdf3;
  border: 1px solid #a7f3d0;
  border-radius: 10px;
  padding: 18px;
  margin-bottom: 20px;
}

.warning {
  background: #fff7ed;
  border: 1px solid #fed7aa;
  border-radius: 10px;
  padding: 18px;
  margin-top: 20px;
}

.error {
  background: #fef2f2;
  border: 1px solid #fecaca;
  border-radius: 10px;
  padding: 18px;
}

pre {
  white-space: pre-wrap;
  word-break: break-word;
  background: #111827;
  color: white;
  padding: 15px;
  border-radius: 10px;
  overflow-x: auto;
}

footer {
  text-align: center;
  padding: 30px;
  color: #667085;
}

.small {
  color: #667085;
  font-size: 14px;
}

</style>

</head>

<body>

<nav>

<a href="/">Home</a>

<a href="/privacy">
Privacy
</a>

<a href="/terms">
Terms
</a>

<a href="/health">
Health
</a>

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

</html>
`;
}


/* ================================
   HOME
================================ */

app.get("/", (req, res) => {

  res.send(
    page(
      "X OAuth 2.0",
      `

<h1>Connect with X</h1>

<p>
This application demonstrates
X OAuth 2.0 Authorization Code
with PKCE.
</p>

<div class="info">

<strong>Base URL</strong>

<br>

${escapeHtml(
  BASE_URL || "Not configured"
)}

</div>


<div class="info">

<strong>Callback URL</strong>

<br>

${escapeHtml(
  REDIRECT_URI
)}

</div>


<a href="/auth/x">

<button>
Connect X Account
</button>

</a>

`
    )
  );
});


/* ================================
   HEALTH CHECK
================================ */

app.get("/health", (req, res) => {

  res.json({

    status: "ok",

    service:
      "X OAuth 2.0 Application",

    base_url:
      BASE_URL,

    callback:
      REDIRECT_URI

  });

});


/* ================================
   START OAUTH
================================ */

app.get("/auth/x", (req, res) => {

  if (!X_CLIENT_ID || !BASE_URL) {

    return res.status(500).send(

      page(
        "Configuration Error",
        `

<h1>Configuration Error</h1>

<p>
Missing:
<strong>
X_CLIENT_ID
</strong>
or
<strong>
BASE_URL
</strong>.
</p>

`
      )

    );

  }


  /*
   Generate CSRF state
  */

  const state =
    crypto
      .randomBytes(32)
      .toString("hex");


  /*
   Generate PKCE verifier
  */

  const verifier =
    crypto
      .randomBytes(32)
      .toString("base64url");


  /*
   Generate PKCE challenge
  */

  const challenge =
    crypto
      .createHash("sha256")
      .update(verifier)
      .digest("base64url");


  /*
   Store verifier temporarily
  */

  sessions.set(

    state,

    {
      verifier,
      created: Date.now()
    }

  );


  /*
   Remove expired sessions
  */

  for (
    const [key, value]
    of sessions.entries()
  ) {

    if (
      Date.now() -
      value.created >
      10 * 60 * 1000
    ) {

      sessions.delete(key);

    }

  }


  /*
   OAuth scopes
  */

  const scope =
    "tweet.read users.read";


  /*
   Authorization parameters
  */

  const params =
    new URLSearchParams({

      response_type:
        "code",

      client_id:
        X_CLIENT_ID,

      redirect_uri:
        REDIRECT_URI,

      scope:
        scope,

      state:
        state,

      code_challenge:
        challenge,

      code_challenge_method:
        "S256"

    });


  const authorizationUrl =
    `https://x.com/i/oauth2/authorize?${params.toString()}`;


  console.log(
    "Starting X OAuth authorization..."
  );


  res.redirect(
    authorizationUrl
  );

});


/* ================================
   OAUTH CALLBACK
================================ */

app.get(
  "/auth/x/callback",
  async (req, res) => {

    const {
      code,
      state,
      error,
      error_description
    } = req.query;


    /*
     X returned an OAuth error
    */

    if (error) {

      return res
        .status(400)
        .send(

          page(
            "X OAuth Error",
            `

<h1>
Authorization Failed
</h1>

<div class="error">

<strong>
Error:
</strong>

${escapeHtml(error)}

<br><br>

<strong>
Description:
</strong>

${escapeHtml(
  error_description ||
  "No description provided"
)}

</div>

<br>

<a href="/auth/x">

<button>
Try Again
</button>

</a>

`
          )

        );

    }


    /*
     Check authorization code
    */

    if (!code || !state) {

      return res
        .status(400)
        .send(

          page(
            "OAuth Error",
            `

<h1>
Missing Authorization Data
</h1>

<p>
X did not return the required
authorization code or state.
</p>

<a href="/auth/x">

<button>
Try Again
</button>

</a>

`
          )

        );

    }


    /*
     Retrieve PKCE verifier
    */

    const session =
      sessions.get(state);


    if (!session) {

      return res
        .status(400)
        .send(

          page(
            "OAuth Error",
            `

<h1>
Invalid or Expired Session
</h1>

<p>
The PKCE session could not be found.
Please start authorization again.
</p>

<a href="/auth/x">

<button>
Try Again
</button>

</a>

`
          )

        );

    }


    /*
     Delete used state
    */

    sessions.delete(state);


    try {

      /*
       Prepare token request
      */

      const tokenBody =
        new URLSearchParams({

          code:
            code,

          grant_type:
            "authorization_code",

          redirect_uri:
            REDIRECT_URI,

          code_verifier:
            session.verifier

        });


      const headers = {

        "Content-Type":
          "application/x-www-form-urlencoded"

      };


      /*
       If Client Secret exists,
       authenticate confidential client.
      */

      if (X_CLIENT_SECRET) {

        const basicAuth =
          Buffer
            .from(
              `${X_CLIENT_ID}:${X_CLIENT_SECRET}`
            )
            .toString("base64");


        headers.Authorization =
          `Basic ${basicAuth}`;

      }

      /*
       Otherwise send Client ID
       for public PKCE client.
      */

      else {

        tokenBody.set(
          "client_id",
          X_CLIENT_ID
        );

      }


      console.log(
        "Exchanging authorization code..."
      );


      /*
       Exchange code for token
      */

      const response =
        await fetch(

          "https://api.x.com/2/oauth2/token",

          {

            method:
              "POST",

            headers:
              headers,

            body:
              tokenBody

          }

        );


      /*
       Read raw response first
      */

      const raw =
        await response.text();


      let data;

      try {

        data =
          JSON.parse(raw);

      }

      catch {

        data = {

          raw_response:
            raw

        };

      }


      console.log(
        "X token response status:",
        response.status
      );


      /*
       Token exchange failed
      */

      if (!response.ok) {

        console.error(
          "X token exchange error:",
          data
        );


        return res
          .status(response.status)
          .send(

            page(
              "Token Exchange Failed",
              `

<h1>
Token Exchange Failed
</h1>

<p>
X returned HTTP status:
<strong>
${response.status}
</strong>
</p>

<pre>${escapeHtml(
  JSON.stringify(
    data,
    null,
    2
  )
)}</pre>

<a href="/auth/x">

<button>
Try Again
</button>

</a>

`
            )

          );

      }


      /*
       Verify access token
      */

      if (!data.access_token) {

        return res
          .status(500)
          .send(

            page(
              "Token Error",
              `

<h1>
No Access Token Returned
</h1>

<pre>${escapeHtml(
  JSON.stringify(
    data,
    null,
    2
  )
)}</pre>

`
            )

          );

      }


      /*
       Extract token information
      */

      const accessToken =
        data.access_token;

      const tokenType =
        data.token_type ||
        "Bearer";

      const expiresIn =
        data.expires_in ||
        "N/A";

      const scope =
        data.scope ||
        "N/A";


      console.log(
        "OAuth access token received successfully."
      );


      /*
       DISPLAY TOKEN IN BROWSER
      */

      return res.send(

        page(
          "Access Token",
          `

<div class="success">

<h1>
✓ Authorization Successful
</h1>

<p>
X OAuth 2.0 authorization
completed successfully.
</p>

</div>


<h2>
Access Token
</h2>


<textarea
id="accessToken"
spellcheck="false"
autocomplete="off"
>${escapeHtml(accessToken)}</textarea>


<br>


<button
onclick="copyToken()"
>
Copy Access Token
</button>


<button
onclick="selectToken()"
>
Select Token
</button>


<div class="info">

<p>

<strong>
Token Type:
</strong>

${escapeHtml(tokenType)}

</p>


<p>

<strong>
Expires In:
</strong>

${escapeHtml(expiresIn)}

seconds

</p>


<p>

<strong>
Scope:
</strong>

${escapeHtml(scope)}

</p>

</div>


<div class="warning">

<strong>
Security Warning
</strong>

<p>
This is a live OAuth credential.
Do not publish it, commit it to
GitHub, or send it to other people.
</p>

</div>


<script>

function selectToken() {

  const box =
    document.getElementById(
      "accessToken"
    );

  box.focus();

  box.select();

}


async function copyToken() {

  const box =
    document.getElementById(
      "accessToken"
    );

  try {

    await navigator.clipboard.writeText(
      box.value
    );

    alert(
      "Access token copied."
    );

  }

  catch (error) {

    box.focus();

    box.select();

    document.execCommand(
      "copy"
    );

    alert(
      "Access token selected."
    );

  }

}

</script>

`
        )

      );


    }

    catch (err) {

      console.error(
        "OAuth callback error:",
        err
      );


      return res
        .status(500)
        .send(

          page(
            "Server Error",
            `

<h1>
OAuth Server Error
</h1>

<p>
The server could not complete
the OAuth token exchange.
</p>

<pre>${escapeHtml(
  err.stack ||
  err.message
)}</pre>

<a href="/auth/x">

<button>
Try Again
</button>

</a>

`
          )

        );

    }

  }
);


/* ================================
   PRIVACY POLICY
================================ */

app.get(
  "/privacy",
  (req, res) => {

    res.send(

      page(
        "Privacy Policy",
        `

<h1>
Privacy Policy
</h1>

<p>
This application uses X OAuth 2.0
to authenticate users who choose
to connect their X account.
</p>

<p>
The application requests only the
permissions necessary for its
functionality.
</p>

<p>
Authentication information is used
only for the functionality requested
by the user.
</p>

<p>
We do not sell personal information.
</p>

<p>
Users may revoke the application's
access through their X account
settings.
</p>

`
      )

    );

  }
);


/* ================================
   TERMS
================================ */

app.get(
  "/terms",
  (req, res) => {

    res.send(

      page(
        "Terms of Service",
        `

<h1>
Terms of Service
</h1>

<p>
By using this application, you agree
to use it lawfully and only with
accounts you are authorized to access.
</p>

<p>
The application is provided for
legitimate authentication and
development purposes.
</p>

<p>
Users are responsible for complying
with X's applicable terms, policies
and developer requirements.
</p>

<p>
Users must not use this application
to obtain unauthorized access to
another person's account.
</p>

`
      )

    );

  }
);


/* ================================
   START SERVER
================================ */

app.listen(
  PORT,
  () => {

    console.log(
      "================================"
    );

    console.log(
      "X OAuth 2.0 Application"
    );

    console.log(
      "================================"
    );

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
      "PKCE: ENABLED"
    );

    console.log(
      "================================"
    );

  }
);

After deploying, use:

https://xauth-v52j.onrender.com/auth/x

The sequence is:

X authorization → "/auth/x/callback" → token exchange → browser displays the returned access token.

If the browser instead shows “Token Exchange Failed”, the page will now display X's actual HTTP status and response, which is the information needed to fix the OAuth configuration.
