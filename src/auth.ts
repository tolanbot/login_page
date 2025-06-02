// src/auth.ts
import jwt from "jsonwebtoken";
import { config } from "dotenv";
config();

const JWT_SECRET = process.env.JWT_SECRET!;

export function generateToken(payload: { email: string; name: string }) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });
}

export function verifyToken(token: string) {
  return jwt.verify(token, JWT_SECRET) as {
    email: string;
    name: string;
    iat: number;
    exp: number;
  };
}
