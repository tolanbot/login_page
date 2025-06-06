import { pool } from "./db";
import bcrypt from "bcrypt";

export type User = {
  id: number;
  name: string;
  email: string;
  password: string;
};

export type GetAllUsersResult =
  | { success: true; users: User[] }
  | { success: false; error: string };

export type Result = { success: true } | { success: false; error: string };

export type AuthResult =
  | { success: true; name: string }
  | { success: false; error: string };

export type PublicUser = {
  name: string;
  email: string;
};

export async function createUser(
  name: string,
  email: string,
  password: string
): Promise<Result> {
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (name,email,password) VALUES ($1, $2, $3)`,
      [name, email, hashedPassword]
    );
    if (result.rowCount && result.rowCount > 0) {
      return { success: true };
    } else {
      return { success: false, error: "Create user failed." };
    }
  } catch (err: any) {
    if (err.code === "23505") {
      return { success: false, error: "Email already exists" };
    }
    return { success: false, error: "Database error" };
  }
}

export async function getUser(email: string): Promise<User | undefined> {
  try {
    const result = await pool.query(`SELECT * FROM users WHERE email = $1`, [
      email,
    ]);
    return result.rows[0];
  } catch (err) {
    return undefined;
  }
}

export async function deleteUser(email: string): Promise<Result> {
  try {
    const result = await pool.query(`DELETE FROM users WHERE email = $1`, [
      email,
    ]);
    if (result.rowCount !== null && result.rowCount > 0) {
      return { success: true };
    } else {
      return { success: false, error: "User not found" };
    }
  } catch (err) {
    return { success: false, error: "Database error" };
  }
}

export async function authenticateUser(
  email: string,
  password: string
): Promise<AuthResult> {
  try {
    const result = await pool.query(
      `SELECT name,password FROM users WHERE email = $1`,
      [email]
    );
    if (result.rows.length === 0) {
      return { success: false, error: "User not found" };
    }
    const storedHash = result.rows[0].password;
    const isMatch = await bcrypt.compare(password, storedHash);
    const name = result.rows[0].name;

    if (isMatch) {
      return { success: true, name };
    } else {
      return { success: false, error: "Incorrect password entered" };
    }
  } catch (err) {
    return { success: false, error: "Database error" };
  }
}

export async function verifyPassword(
  email: string,
  inputPassword: string
): Promise<boolean> {
  try {
    const result = await pool.query(
      `SELECT name, password FROM users WHERE email = $1`,
      [email]
    );
    if (result.rows.length === 0) {
      return false;
    }
    return await bcrypt.compare(inputPassword, result.rows[0].password);
  } catch (err) {
    return false;
  }
}

export async function updatePassword(
  email: string,
  newPassword: string
): Promise<Result> {
  try {
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    const result = await pool.query(
      "UPDATE users SET password = $1 where email = $2",
      [hashedNewPassword, email]
    );
    if (result.rowCount && result.rowCount > 0) {
      return { success: true };
    } else {
      return { success: false, error: "User not found in update function." };
    }
  } catch (err) {
    return { success: false, error: "Database Error" };
  }
}

export async function getAllUsers(): Promise<GetAllUsersResult> {
  try {
    const result = await pool.query(`SELECT * FROM users`);
    return { success: true, users: result.rows };
  } catch (err) {
    return { success: false, error: "Database error" };
  }
}
