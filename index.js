import express from "express";
import cors from "cors";
import {
  authenticateUser,
  registerUser,
  createAccessToken,
} from "./auth.js";
import { verifyToken } from "./security.js";
import { router as devicesRouter } from "./devices.js";

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

app.get("/", (req, res) => {
  res.json({ message: "LogGuard API running" });
});

// ---------------- LOGIN / REGISTER ----------------
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  const user = authenticateUser(email, password);

  if (!user) return res.json({ error: "invalid credentials" });

  const token = createAccessToken({ sub: user.email });
  res.json({ access_token: token });
});

app.post("/register", (req, res) => {
  const { email, password } = req.body;
  const success = registerUser(email, password);

  if (!success) return res.json({ error: "User already exists" });
  res.json({ message: "User registered successfully" });
});

// Example of a human-authenticated route, if you need one later:
app.get("/me", verifyToken, (req, res) => {
  res.json({ email: req.user });
});

app.use(devicesRouter);

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
  console.log(`LogGuard API listening on port ${PORT}`);
});
