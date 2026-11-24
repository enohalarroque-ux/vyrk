const express = require("express");
const crypto = require("crypto");
const { Pool } = require("pg");
const Stripe = require("stripe");

const app = express();
app.set("trust proxy", 1); // derrière le proxy Railway : req.protocol = https
const PLANS = {
  basic: { name: "vyrk BASIC", amount: 299, weekly: 3 },
  premium: { name: "vyrk PREMIUM", amount: 499, weekly: Infinity },
};
const FREE_TOTAL = 1; // séances offertes sans abonnement
const WEEK = "7 days";
const ACTIVE = ["trialing", "active"];

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: false,
});
pool.on("error", (e) => console.error("pg idle", e.message)); // évite un crash sur coupure de connexion
const stripe = process.env.STRIPE_SECRET_KEY ? new Stripe(process.env.STRIPE_SECRET_KEY) : null;

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      pass_hash TEXT NOT NULL,
      stripe_customer_id TEXT,
      plan TEXT,
      sub_status TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS workouts (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );`);
}

// ---- mots de passe (scrypt) ----
function hashPw(pw) {
  const salt = crypto.randomBytes(16);
  const h = crypto.scryptSync(pw, salt, 64);
  return salt.toString("hex") + ":" + h.toString("hex");
}
function checkPw(pw, stored) {
  const [s, h] = stored.split(":");
  const x = crypto.scryptSync(pw, Buffer.from(s, "hex"), 64);
  return crypto.timingSafeEqual(x, Buffer.from(h, "hex"));
}

// ---- sessions (cookie) ----
const COOKIE = "vyrk_s";
function cookies(req) {
  const o = {};
  (req.headers.cookie || "").split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return o;
}
function setCookie(res, token, maxAge) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  res.setHeader("Set-Cookie", `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`);
}
async function newSession(res, userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await pool.query("INSERT INTO sessions(token,user_id) VALUES($1,$2)", [token, userId]);
  setCookie(res, token, 60 * 60 * 24 * 90);
}
async function auth(req, _res, next) {
  try {
    const t = cookies(req)[COOKIE];
    req.user = null;
    if (t) {
      const r = await pool.query(
        "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=$1",
        [t]
      );
      req.user = r.rows[0] || null;
    }
    next();
  } catch (e) {
    next(e);
  }
}
const need = (req, res, next) => (req.user ? next() : res.status(401).json({ error: "Connexion requise" }));

// ---- abonnement / quota ----
function effectivePlan(u) {
  return u.plan && ACTIVE.includes(u.sub_status) ? u.plan : null;
}
async function usage(u) {
  const plan = effectivePlan(u);
  if (plan === "premium") return { plan, used: 0, limit: null, period: "week" };
  if (plan === "basic") {
    const r = await pool.query(
      `SELECT count(*)::int n FROM workouts WHERE user_id=$1 AND created_at > now() - interval '${WEEK}'`,
      [u.id]
    );
    return { plan, used: r.rows[0].n, limit: PLANS.basic.weekly, period: "week" };
  }
  const r = await pool.query("SELECT count(*)::int n FROM workouts WHERE user_id=$1", [u.id]);
  return { plan: null, used: r.rows[0].n, limit: FREE_TOTAL, period: "total" };
}
const publicUser = async (u) => ({
  user: { name: u.name, email: u.email },
  subscription: await usage(u),
});

async function syncSubscription(sub) {
  const userId = sub.metadata && sub.metadata.user_id;
  const plan = sub.metadata && sub.metadata.plan;
  const customer = typeof sub.customer === "string" ? sub.customer : sub.customer.id;
  if (userId) {
    await pool.query(
      "UPDATE users SET stripe_customer_id=$1, plan=$2, sub_status=$3 WHERE id=$4",
      [customer, plan, sub.status, userId]
    );
  } else {
    await pool.query("UPDATE users SET sub_status=$1 WHERE stripe_customer_id=$2", [sub.status, customer]);
  }
}

// ---- webhook Stripe (corps brut, avant express.json) ----
app.post("/api/stripe-webhook", express.raw({ type: "application/json" }), async (req, res) => {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  if (!stripe || !secret) return res.status(500).send("webhook non configuré");
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, req.headers["stripe-signature"], secret);
  } catch (e) {
    return res.status(400).send("signature invalide");
  }
  try {
    if (event.type === "checkout.session.completed") {
      const s = event.data.object;
      if (s.subscription) await syncSubscription(await stripe.subscriptions.retrieve(s.subscription));
    } else if (
      event.type === "customer.subscription.created" ||
      event.type === "customer.subscription.updated" ||
      event.type === "customer.subscription.deleted"
    ) {
      await syncSubscription(event.data.object);
    }
    res.json({ received: true });
  } catch (e) {
    console.error("webhook", e.message);
    res.status(500).send("erreur");
  }
});

app.use(express.json());
app.use(auth);

// ---- comptes ----
const emailOk = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e);
app.post("/api/register", async (req, res) => {
  const name = String((req.body && req.body.name) || "").trim().slice(0, 60);
  const email = String((req.body && req.body.email) || "").trim().toLowerCase();
  const pw = String((req.body && req.body.password) || "");
  if (!name || !emailOk(email)) return res.status(400).json({ error: "Prénom ou e-mail invalide." });
  if (pw.length < 8) return res.status(400).json({ error: "Mot de passe : 8 caractères minimum." });
  try {
    const r = await pool.query(
      "INSERT INTO users(name,email,pass_hash) VALUES($1,$2,$3) RETURNING *",
      [name, email, hashPw(pw)]
    );
    await newSession(res, r.rows[0].id);
    res.json(await publicUser(r.rows[0]));
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "Cet e-mail a déjà un compte." });
    console.error(e.message);
    res.status(500).json({ error: "Erreur serveur" });
  }
});
app.post("/api/login", async (req, res) => {
  const email = String((req.body && req.body.email) || "").trim().toLowerCase();
  const pw = String((req.body && req.body.password) || "");
  const r = await pool.query("SELECT * FROM users WHERE email=$1", [email]);
  const u = r.rows[0];
  if (!u || !checkPw(pw, u.pass_hash)) return res.status(401).json({ error: "E-mail ou mot de passe incorrect." });
  await newSession(res, u.id);
  res.json(await publicUser(u));
});
app.post("/api/logout", async (req, res) => {
  const t = cookies(req)[COOKIE];
  if (t) await pool.query("DELETE FROM sessions WHERE token=$1", [t]);
  setCookie(res, "", 0);
  res.json({ ok: true });
});
app.get("/api/me", (req, res) =>
  req.user ? publicUser(req.user).then((d) => res.json(d)) : res.json({ user: null })
);

// ---- séances : le quota est vérifié ici ----
app.post("/api/workout/start", need, async (req, res) => {
  const u = await usage(req.user);
  if (u.limit !== null && u.used >= u.limit) {
    return res.status(403).json({ error: "limit", subscription: u });
  }
  await pool.query("INSERT INTO workouts(user_id) VALUES($1)", [req.user.id]);
  res.json({ ok: true, subscription: await usage(req.user) });
});

// ---- paiement ----
app.post("/api/checkout", need, async (req, res) => {
  if (!stripe) return res.status(500).json({ error: "STRIPE_SECRET_KEY manquante" });
  const key = req.body && req.body.plan;
  const plan = PLANS[key];
  if (!plan) return res.status(400).json({ error: "Offre inconnue" });
  const u = req.user;
  if (effectivePlan(u)) return res.status(409).json({ error: "Tu as déjà un abonnement actif." });
  const origin = process.env.PUBLIC_URL || `${req.protocol}://${req.get("host")}`;
  try {
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      ...(u.stripe_customer_id ? { customer: u.stripe_customer_id } : { customer_email: u.email }),
      client_reference_id: String(u.id),
      line_items: [{
        quantity: 1,
        price_data: {
          currency: "eur",
          unit_amount: plan.amount,
          recurring: { interval: "month" },
          product_data: { name: plan.name },
        },
      }],
      subscription_data: { ...(u.stripe_customer_id ? {} : { trial_period_days: 30 }), metadata: { user_id: String(u.id), plan: key } },
      allow_promotion_codes: true,
      success_url: `${origin}/?session_id={CHECKOUT_SESSION_ID}#abonnement`,
      cancel_url: `${origin}/#abonnement`,
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: "Paiement indisponible" });
  }
});
// Au retour de Stripe, on synchronise sans attendre le webhook.
app.post("/api/checkout/confirm", need, async (req, res) => {
  try {
    const s = await stripe.checkout.sessions.retrieve(String(req.body.session_id));
    if (s.client_reference_id === String(req.user.id) && s.subscription) {
      await syncSubscription(await stripe.subscriptions.retrieve(s.subscription));
    }
    const r = await pool.query("SELECT * FROM users WHERE id=$1", [req.user.id]);
    res.json(await publicUser(r.rows[0]));
  } catch (e) {
    console.error(e.message);
    res.status(400).json({ error: "Session introuvable" });
  }
});
app.post("/api/portal", need, async (req, res) => {
  if (!stripe || !req.user.stripe_customer_id) return res.status(400).json({ error: "Aucun abonnement" });
  const origin = process.env.PUBLIC_URL || `${req.protocol}://${req.get("host")}`;
  const s = await stripe.billingPortal.sessions.create({
    customer: req.user.stripe_customer_id,
    return_url: `${origin}/#abonnement`,
  });
  res.json({ url: s.url });
});

app.use((err, _req, res, _next) => {
  console.error(err.message);
  res.status(500).json({ error: "Erreur serveur" });
});
app.get("/", (_req, res) => res.sendFile(require("path").join(__dirname, "index.html")));

initDb()
  .then(() => app.listen(process.env.PORT || 8080, "0.0.0.0"))
  .catch((e) => {
    console.error("DB:", e.message);
    process.exit(1);
  });
