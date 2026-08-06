import express from "express";
import cors from "cors";
import {
  authenticateUser,
  registerUser,
  createAccessToken,
} from "./auth.js";
import { verifyToken } from "./security.js";
import { router as devicesRouter } from "./devices.js";
import { initDb } from "./database.js";

const app = express();
// FRONTEND_URL restricts CORS to your real dashboard once deployed.
// Falls back to "*" (open) if unset, so this still works before you have
// a Vercel URL yet - set FRONTEND_URL on Render once you do.
app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json());

app.get("/", (req, res) => {
  res.json({ message: "LogGuard API running" });
});

// ---------------- LOGIN / REGISTER ----------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await authenticateUser(email, password);

  if (!user) return res.json({ error: "invalid credentials" });

  const token = createAccessToken({ sub: user.email });
  res.json({ access_token: token });
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  const success = await registerUser(email, password);

  if (!success) return res.json({ error: "User already exists" });
  res.json({ message: "User registered successfully" });
});

app.get("/me", verifyToken, (req, res) => {
  res.json({ email: req.user });
});

app.use(devicesRouter);

const PORT = process.env.PORT || 8000;

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`LogGuard API listening on port ${PORT}`);
  });
});
