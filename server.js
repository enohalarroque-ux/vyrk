const express = require("express");
const path = require("path");
const Stripe = require("stripe");

const app = express();
const PLANS = {
  basic: { name: "vyrk BASIC", amount: 299 },
  premium: { name: "vyrk PREMIUM", amount: 499 },
};

app.use(express.json());

app.post("/api/checkout", async (req, res) => {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) return res.status(500).json({ error: "STRIPE_SECRET_KEY manquante" });
  const plan = PLANS[req.body && req.body.plan];
  if (!plan) return res.status(400).json({ error: "Offre inconnue" });
  const origin = process.env.PUBLIC_URL || `${req.protocol}://${req.get("host")}`;
  try {
    const stripe = new Stripe(key);
    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{
        quantity: 1,
        price_data: {
          currency: "eur",
          unit_amount: plan.amount,
          recurring: { interval: "month" },
          product_data: { name: plan.name },
        },
      }],
      subscription_data: { trial_period_days: 30 },
      allow_promotion_codes: true,
      success_url: `${origin}/#abonnement?paiement=ok`,
      cancel_url: `${origin}/#abonnement`,
    });
    res.json({ url: session.url });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: "Paiement indisponible" });
  }
});

app.use(express.static(__dirname, { index: "index.html", dotfiles: "ignore" }));
app.listen(process.env.PORT || 8080, "0.0.0.0");
