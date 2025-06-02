import express, { Request, Response } from "express";
import rateLimit from "express-rate-limit";
import { generateToken, verifyToken } from "./auth";
import cookieParser from "cookie-parser";
import {
  createUser,
  getAllUsers,
  getUser,
  deleteUser,
  authenticateUser,
  updatePassword,
  verifyPassword,
} from "./users";

import type { User, PublicUser, Result, AuthResult } from "./users";
import type { RequestHandler } from "express";

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: {
    success: false,
    error: "Too many login attempts, please try later",
  },
});

app.post("/login", loginLimiter, async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res
      .status(400)
      .json({ success: false, error: "Missing email, or password." });
    return;
  }

  const result: AuthResult = await authenticateUser(email, password);

  if (result.success) {
    const token = generateToken({ email, name: result.name });
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 60 * 60 * 1000,
    });

    res.status(201).json({
      success: true,
      message: "Login successful",
      username: result.name,
    });
  } else {
    res
      .status(201)
      .json({ success: false, message: "Incorrect username or password" });
  }
});

app.post("/logout", (req: Request, res: Response) => {
  const token = req.cookies.token;
  if (!token || !verifyToken(token)) {
    res.status(401).json({ success: false, error: "invalid or missing token" });
    return;
  }
  res.clearCookie("token", {
    httpOnly: true,
    secure: false,
    sameSite: "lax",
  });
  res.status(200).json({ success: true, message: "Logged out" });
});

app.post("/users", async (req: Request, res: Response) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    res
      .status(400)
      .json({ success: false, error: "Missing name, email, or password." });
    return;
  }
  const cleanName: string = name.trim();
  if (!/^[a-zA-Z0-9]+$/.test(cleanName)) {
    res.status(400).json({ success: false, error: "Invalid name format" });
    return;
  }
  const cleanEmail: string = email.trim();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res
      .status(400)
      .json({ success: false, error: "Email has incorrect formatting." });
    return;
  }
  const cleanPassword: string = password.trim();
  if (
    !/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/.test(password)
  ) {
    res.status(400).json({
      success: false,
      error:
        "Strong password must be at least 8 characters and contain: one lowercase letter, one uppercase letter, one digit, one special character.",
    });
    return;
  }

  const newUserResult: Result = await createUser(
    cleanName,
    cleanEmail,
    cleanPassword
  );
  if (newUserResult.success === true) {
    res.status(201).json({ success: true });
  } else {
    res.status(409).json({ success: false, error: newUserResult.error });
  }
});

const patchLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 min
  max: 5, // limit each IP to 5 attempts
  message: "Too many password change attempts. Try again later.",
});

app.patch(
  "/users/:email",
  patchLimiter as RequestHandler,
  async (req: Request, res: Response) => {
    const token = req.cookies.token;
    if (!token) {
      res.status(401).json({ success: false, error: "Unauthorized" });
      return;
    }
    const user = verifyToken(token);
    if (!user) {
      res.status(403).json({ success: false, error: "Invalid Token" });
      return;
    }

    const email = req.params.email;
    const { oldPassword, newPassword, confirmPassword } = req.body;
    if (!oldPassword || !newPassword || !confirmPassword) {
      res
        .status(400)
        .json({ success: false, error: "Missing password information" });
      return;
    }

    if (newPassword === oldPassword) {
      res.status(200).json({
        success: false,
        error: "New password must be different than old password",
      });
      return;
    }

    const oldPasswordMatches = await verifyPassword(email, oldPassword);
    if (!oldPasswordMatches) {
      res.status(200).json({
        success: false,
        error: "Entered Old password does not mach old password",
      });
      return;
    }
    if (newPassword !== confirmPassword) {
      res.status(200).json({
        success: false,
        error: "new password and confirm password does not match",
      });
      return;
    }

    const isStrongPassword =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/.test(
        newPassword
      );

    if (!isStrongPassword) {
      res.status(400).json({
        success: false,
        error:
          "Password must be at least 8 characters and include lowercase, uppercase, number, and special character.",
      });
      return;
    }

    const updated: Result = await updatePassword(email, newPassword);
    if (updated.success) {
      res.json({ success: true, message: "Password successfully updated" });
    } else {
      res.status(500).json({ success: false, error: updated.error });
    }
  }
);

app.get("/me", (req: Request, res: Response) => {
  const token = req.cookies.token;
  if (!token) {
    res.json({ success: false, loggedIn: false });
    return;
  }
  const user = verifyToken(token);
  if (!user) {
    res.json({ success: false, loggedIn: false });
    return;
  }
  res.json({
    success: true,
    loggedIn: true,
    name: user.name,
    email: user.email,
  });
});

app.get("/users", async (req: Request, res: Response) => {
  const allUsers = await getAllUsers();
  res.json(allUsers);
});

app.get("/users/:email", async (req: Request, res: Response) => {
  const user: User | undefined = await getUser(req.params.email);
  if (user) {
    const publicUser: PublicUser = { name: user.name, email: user.email };
    res.json({ success: true, user: publicUser });
  } else {
    res.status(404).json({ success: false, error: "User not found" });
  }
});

app.delete("/users/:email", async (req: Request, res: Response) => {
  const deleted: Result = await deleteUser(req.params.email);
  if (deleted.success) {
    res.json({ success: true });
  } else {
    res.status(404).json({ success: false, error: "User not found" });
  }
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});
