import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { db } from "./database.js";

const SECRET_KEY = process.env.JWT_SECRET_KEY || "change-me-in-production";
const ALGORITHM = "HS256";
const ACCESS_TOKEN_EXPIRE_MINUTES = 60;

export function hashPassword(password) {
  return bcrypt.hashSync(password, 10);
}

export function verifyPassword(plain, hashed) {
  return bcrypt.compareSync(plain, hashed);
}

export async function registerUser(email, password) {
  const existing = await db.execute({
    sql: "SELECT id FROM users WHERE email = ?",
    args: [email],
  });
  if (existing.rows.length > 0) return false;

  await db.execute({
    sql: "INSERT INTO users (email, password) VALUES (?, ?)",
    args: [email, hashPassword(password)],
  });
  return true;
}

export async function authenticateUser(email, password) {
  const result = await db.execute({
    sql: "SELECT * FROM users WHERE email = ?",
    args: [email],
  });
  const user = result.rows[0];
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
