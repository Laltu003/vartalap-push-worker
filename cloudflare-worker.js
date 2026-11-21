// Vartalap backend: FCM push notifications + email OTP password reset.
// Secrets: FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY,
//          BREVO_API_KEY, MAIL_FROM_EMAIL, OTP_SALT

const OTP_TTL_MS = 10 * 60 * 1000;     // a code is valid for 10 minutes
const TICKET_TTL_MS = 10 * 60 * 1000;  // after verifying, the reset window is 10 minutes
const RESEND_COOLDOWN_MS = 60 * 1000;  // minimum gap between codes for one email
const MAX_ATTEMPTS = 5;                // wrong codes allowed before a new code is needed

class UserError extends Error {}

// A required secret is missing or weak. The Worker refuses to serve rather than run insecurely.
class ConfigError extends Error {}

const OTP_ROUTES = ["/otp/request", "/otp/verify", "/password/reset"];

function requireSecrets(env, names) {
  for (const name of names) {
    if (!env[name]) throw new ConfigError(`Missing secret: ${name}`);
  }
  if (env.OTP_SALT.length < 16) throw new ConfigError("OTP_SALT must be at least 16 characters");
}

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return text("Method not allowed", 405);
    }
    const path = new URL(request.url).pathname;
    const isPush = path === "/" || path === "/push";
    try {
      // Every route needs the Firebase service account; email codes also need Brevo.
      requireSecrets(env, ["FIREBASE_PROJECT_ID", "FIREBASE_CLIENT_EMAIL", "FIREBASE_PRIVATE_KEY"]);
      if (OTP_ROUTES.includes(path)) {
        requireSecrets(env, ["OTP_SALT", "BREVO_API_KEY", "MAIL_FROM_EMAIL"]);
      }
      const body = await request.json();
      if (isPush) return await handlePush(body, env);
      if (path === "/otp/request") return await handleOtpRequest(body, env);
      if (path === "/otp/verify") return await handleOtpVerify(body, env);
      if (path === "/password/reset") return await handlePasswordReset(body, env);
      if (path === "/auth/resolve-login") return await handleResolveLogin(body, env);
      if (path === "/auth/check") return await handleAvailability(body, env);
      return text("Not found", 404);
    } catch (err) {
      if (err instanceof UserError) return text(err.message, 400);
      if (err instanceof ConfigError) {
        console.error(err.message); // shows in the Cloudflare dashboard logs
        return text("This service is temporarily unavailable. Please try again later.", 503);
      }
      console.error(err);
      return text(isPush ? "Error: " + err.message : "Something went wrong. Please try again.", 500);
    }
  },
};

// ---------------------------------------------------------------- push (unchanged behaviour)

async function handlePush(payload, env) {
  requireSecrets(env, ["FIREBASE_WEB_API_KEY"]);
  const { idToken, chatId, recipientUid } = payload;
  const messageText = String(payload.body || "").slice(0, 200);
  if (!idToken || !chatId || !recipientUid) throw new UserError("Missing push details");

  // Only a signed-in user can send, and only to someone in a chat they share.
  const senderUid = await verifyIdToken(idToken, env);
  const accessToken = await getAccessToken(env);

  const chatFields = await getRawDoc(env, accessToken, "chats", chatId);
  const participants = chatFields && chatFields.participants
    ? (chatFields.participants.arrayValue?.values || []).map((v) => v.stringValue)
    : [];
  if (!participants.includes(senderUid) || !participants.includes(recipientUid)) {
    throw new UserError("You can only notify people in your own chats.");
  }

  const tokenDoc = await getDoc(env, accessToken, "fcmTokens", recipientUid);
  if (!tokenDoc || !tokenDoc.token) return json({ skipped: "no device token" });

  // The title comes from the server-side profile, so the client can't pretend to be someone else.
  const senderDoc = await getDoc(env, accessToken, "users", senderUid);
  const title = (senderDoc && senderDoc.displayName) || "New message";

  const fcm = await fetch(
    `https://fcm.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/messages:send`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        message: {
          token: tokenDoc.token,
          notification: { title, body: messageText || "Sent an attachment" },
          data: { chatId },
          android: { priority: "high", notification: { sound: "default" } },
        },
      }),
    }
  );
  return text(await fcm.text(), fcm.status);
}

// ---------------------------------------------------------------- password reset by email code

async function handleOtpRequest(payload, env) {
  const email = normaliseEmail(payload.email);
  const accessToken = await getAccessToken(env);

  // Always answer the same way, whether or not the account exists,
  // so the endpoint can't be used to discover which emails are registered.
  const account = await findAccount(email, accessToken);
  if (account) {
    const docId = await sha256Hex(email);
    const now = Date.now();
    const record = await firestoreGet(env, accessToken, docId);
    const cooling = record && now - record.lastSentAt < RESEND_COOLDOWN_MS;
    if (!cooling) {
      const code = randomCode();
      await firestoreSet(env, accessToken, docId, {
        codeHash: await sha256Hex(`${env.OTP_SALT}:${email}:${code}`),
        expiresAt: now + OTP_TTL_MS,
        attempts: 0,
        lastSentAt: now,
        ticketHash: "",
        ticketExpiresAt: 0,
      });
      await sendOtpEmail(env, email, code);
    }
  }
  return json({ ok: true });
}

async function handleOtpVerify(payload, env) {
  const email = normaliseEmail(payload.email);
  const code = String(payload.code || "").trim();
  if (!/^\d{6}$/.test(code)) throw new UserError("Enter the 6-digit code from your email.");

  const accessToken = await getAccessToken(env);
  const docId = await sha256Hex(email);
  const now = Date.now();
  const record = await firestoreGet(env, accessToken, docId);

  if (!record || !record.codeHash) {
    throw new UserError("That code is invalid or has expired. Request a new one.");
  }
  if (now > record.expiresAt) {
    throw new UserError("That code has expired. Request a new one.");
  }
  if (record.attempts >= MAX_ATTEMPTS) {
    throw new UserError("Too many wrong attempts. Request a new code.");
  }

  const expected = await sha256Hex(`${env.OTP_SALT}:${email}:${code}`);
  if (expected !== record.codeHash) {
    await firestoreSet(env, accessToken, docId, { ...record, attempts: record.attempts + 1 });
    throw new UserError("That code is incorrect.");
  }

  // Code accepted: make it single-use and hand back a short-lived reset ticket.
  const ticket = randomHex(32);
  await firestoreSet(env, accessToken, docId, {
    codeHash: "",
    expiresAt: 0,
    attempts: 0,
    lastSentAt: record.lastSentAt,
    ticketHash: await sha256Hex(ticket),
    ticketExpiresAt: now + TICKET_TTL_MS,
  });
  return json({ ticket });
}

async function handlePasswordReset(payload, env) {
  const email = normaliseEmail(payload.email);
  const ticket = String(payload.ticket || "");
  const newPassword = String(payload.newPassword || "");
  if (newPassword.length < 6) throw new UserError("Password must be at least 6 characters.");

  const accessToken = await getAccessToken(env);
  const docId = await sha256Hex(email);
  const now = Date.now();
  const record = await firestoreGet(env, accessToken, docId);

  if (!record || !record.ticketHash || now > record.ticketExpiresAt) {
    throw new UserError("This reset session has expired. Start again.");
  }
  if ((await sha256Hex(ticket)) !== record.ticketHash) {
    throw new UserError("This reset session is invalid. Start again.");
  }

  const account = await findAccount(email, accessToken);
  if (!account) throw new UserError("This reset session is invalid. Start again.");

  const res = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:update", {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ localId: account.localId, password: newPassword }),
  });
  if (!res.ok) throw new Error("Password update failed: " + res.status + " " + (await res.text()));

  await firestoreDelete(env, accessToken, docId);
  return json({ ok: true });
}

// ---------------------------------------------------------------- helpers

async function findAccount(email, accessToken) {
  const res = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup", {
    method: "POST",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ email: [email] }),
  });
  if (!res.ok) throw new Error("Account lookup failed: " + res.status + " " + (await res.text()));
  const data = await res.json();
  return data.users && data.users.length ? data.users[0] : null;
}

async function sendOtpEmail(env, email, code) {
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      sender: { email: env.MAIL_FROM_EMAIL, name: "Vartalap" },
      to: [{ email }],
      subject: `Your Vartalap code: ${code}`,
      htmlContent:
        `<p>Your Vartalap password reset code is:</p>` +
        `<p style="font-size:24px;font-weight:bold;letter-spacing:4px">${code}</p>` +
        `<p>It expires in 10 minutes. If you didn't ask to reset your password, you can ignore this email.</p>`,
    }),
  });
  if (!res.ok) throw new Error("Email send failed: " + res.status + " " + (await res.text()));
}

function resetDocUrl(env, docId) {
  return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/passwordResets/${docId}`;
}

async function firestoreGet(env, accessToken, docId) {
  const res = await fetch(resetDocUrl(env, docId), { headers: { Authorization: `Bearer ${accessToken}` } });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Firestore read failed: " + res.status + " " + (await res.text()));
  const doc = await res.json();
  return decodeFields(doc.fields || {});
}

async function firestoreSet(env, accessToken, docId, data) {
  // PATCH without an update mask replaces the whole document, so we always write full state.
  const res = await fetch(resetDocUrl(env, docId), {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ fields: encodeFields(data) }),
  });
  if (!res.ok) throw new Error("Firestore write failed: " + res.status + " " + (await res.text()));
}

async function firestoreDelete(env, accessToken, docId) {
  await fetch(resetDocUrl(env, docId), { method: "DELETE", headers: { Authorization: `Bearer ${accessToken}` } });
}

function encodeFields(data) {
  const fields = {};
  for (const [key, value] of Object.entries(data)) {
    fields[key] = typeof value === "number"
      ? { integerValue: String(Math.round(value)) }
      : { stringValue: String(value ?? "") };
  }
  return fields;
}

function decodeFields(fields) {
  const out = {};
  for (const [key, value] of Object.entries(fields)) {
    out[key] = value.integerValue !== undefined ? Number(value.integerValue) : (value.stringValue ?? "");
  }
  return out;
}

function normaliseEmail(value) {
  const email = String(value || "").trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new UserError("Enter a valid email address.");
  return email;
}

async function sha256Hex(input) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomCode() {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return String(n).padStart(6, "0");
}

function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------- sign-in lookups (server-side)

async function handleResolveLogin(payload, env) {
  const loginId = String(payload.loginId || "").trim();
  if (!loginId) throw new UserError("Enter your email, username or Vartalap ID.");
  if (loginId.includes("@")) return json({ email: loginId.toLowerCase() });

  const accessToken = await getAccessToken(env);
  let user = await findUserByField(env, accessToken, "username", loginId.toLowerCase());
  if (!user) user = await findUserByField(env, accessToken, "vartalapId", loginId.toUpperCase());
  if (!user) throw new UserError(`No account found for "${loginId}".`);

  const privateDoc = await getDoc(env, accessToken, "privateProfiles", user.uid);
  const email = (privateDoc && privateDoc.email) || user.email;
  if (!email) throw new UserError(`No account found for "${loginId}".`);
  return json({ email });
}

async function handleAvailability(payload, env) {
  const accessToken = await getAccessToken(env);
  const result = {};
  if (payload.username) {
    const taken = await findUserByField(env, accessToken, "username", String(payload.username).trim().toLowerCase());
    result.usernameTaken = taken !== null;
  }
  if (payload.vartalapId) {
    const taken = await findUserByField(env, accessToken, "vartalapId", String(payload.vartalapId).trim().toUpperCase());
    result.vartalapIdTaken = taken !== null;
  }
  return json(result);
}

async function findUserByField(env, accessToken, field, value) {
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents:runQuery`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        structuredQuery: {
          from: [{ collectionId: "users" }],
          where: { fieldFilter: { field: { fieldPath: field }, op: "EQUAL", value: { stringValue: value } } },
          limit: 1,
        },
      }),
    }
  );
  if (!res.ok) throw new Error("User lookup failed: " + res.status + " " + (await res.text()));
  const rows = await res.json();
  const found = rows.find((row) => row.document);
  if (!found) return null;
  const fields = decodeFields(found.document.fields || {});
  return { uid: fields.uid, email: fields.email };
}

async function getDoc(env, accessToken, collection, id) {
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${collection}/${id}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Read failed: " + res.status + " " + (await res.text()));
  return decodeFields((await res.json()).fields || {});
}

function text(message, status = 200) {
  return new Response(message, { status });
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
}

async function getAccessToken(env) {
  const privateKey = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n");
  const clientEmail = env.FIREBASE_CLIENT_EMAIL;

  const header = { alg: "RS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const claimSet = {
    iss: clientEmail,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    aud: "https://oauth2.googleapis.com/token",
    exp: now + 3600,
    iat: now,
  };

  const encoder = new TextEncoder();
  const base64url = (data) =>
    btoa(String.fromCharCode(...new Uint8Array(data)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  const base64urlString = (str) =>
    btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const headerB64 = base64urlString(JSON.stringify(header));
  const claimB64 = base64urlString(JSON.stringify(claimSet));
  const unsigned = `${headerB64}.${claimB64}`;

  const pemContents = privateKey
    .replace("-----BEGIN PRIVATE KEY-----", "")
    .replace("-----END PRIVATE KEY-----", "")
    .replace(/\s/g, "");
  const binaryDer = Uint8Array.from(atob(pemContents), (c) => c.charCodeAt(0));

  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", cryptoKey, encoder.encode(unsigned));
  const jwt = `${unsigned}.${base64url(signature)}`;

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  const tokenData = await tokenResponse.json();
  if (!tokenData.access_token) {
    throw new Error("Failed to get access token: " + JSON.stringify(tokenData));
  }
  return tokenData.access_token;
}

// ---------------------------------------------------------------- sender verification (push)

async function verifyIdToken(idToken, env) {
  const res = await fetch(
    `https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=${env.FIREBASE_WEB_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ idToken }),
    }
  );
  if (!res.ok) throw new UserError("Sign in again to continue.");
  const data = await res.json();
  const uid = data.users && data.users[0] && data.users[0].localId;
  if (!uid) throw new UserError("Sign in again to continue.");
  return uid;
}

async function getRawDoc(env, accessToken, collection, id) {
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents/${collection}/${id}`,
    { headers: { Authorization: `Bearer ${accessToken}` } }
  );
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Read failed: " + res.status + " " + (await res.text()));
  return (await res.json()).fields || {};
}
