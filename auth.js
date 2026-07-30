import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { db } from "./database.js";

// Left exactly as-is per your instruction - same env var name/fallback pattern.
const SECRET_KEY = process.env.JWT_SECRET_KEY || "change-me-in-production";
const ALGORITHM = "HS256";
const ACCESS_TOKEN_EXPIRE_MINUTES = 60;

export function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

export function verifyPassword(plain, hashed) {
  return bcrypt.compareSync(plain, hashed);
}

export function registerUser(email, password) {
  const existing = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
  if (existing) return false;

  db.prepare("INSERT INTO users (email, password) VALUES (?, ?)").run(
    email,
    hashPassword(password)
  );
  return true;
}

export function authenticateUser(email, password) {
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
  if (!user) return null;
  if (!verifyPassword(password, user.password)) return null;
  return user;
}

export function createAccessToken(payload) {
  return jwt.sign(payload, SECRET_KEY, {
    algorithm: ALGORITHM,
    expiresIn: `${ACCESS_TOKEN_EXPIRE_MINUTES}m`,
  });
}

export function verifyAccessToken(token) {
  return jwt.verify(token, SECRET_KEY);
}
