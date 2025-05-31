import express, { Request, Response } from "express";
import {
  createUser,
  getAllUsers,
  getUser,
  deleteUser,
  authenticateUser,
  type User,
  type PublicUser,
  type Result,
  type AuthResult,
  updatePassword,
} from "./users";

const app = express();
app.use(express.json());
app.use(express.static("public"));

app.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res
      .status(400)
      .json({ success: false, error: "Missing email, or password." });
    return;
  }

  const result: AuthResult = await authenticateUser(email, password);

  if (result.success) {
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

app.post("/users", async (req: Request, res: Response) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    res
      .status(400)
      .json({ success: false, error: "Missing name, email, or password." });
    return;
  }
  const newUserResult: Result = await createUser(name, email, password);
  if (newUserResult.success === true) {
    res.status(201).json({ success: true });
  } else {
    res.status(409).json({ success: false, error: newUserResult.error });
  }
});

app.patch("/users/:email", async (req: Request, res: Response) => {
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
  const user: User | undefined = await getUser(email);

  if (!user) {
    res.status(404).json({ success: false, error: "User not found in patch." });
    return;
  }
  if (!(oldPassword === user.password)) {
    res.status(200).json({
      success: false,
      error: "Entered Old password does not mach old password",
    });
    return;
  }
  if (!(newPassword === confirmPassword)) {
    res.status(200).json({
      success: false,
      error: "new password and confirm password does not match",
    });
    return;
  }
  const updated: Result = await updatePassword(email, newPassword);
  if (updated.success) {
    res.json({ success: true, message: "Password successfully updated" });
  } else {
    res.status(500).json({ success: false, error: updated.error });
  }
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
