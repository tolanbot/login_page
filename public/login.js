let loggedInEmail = null;
let passwordUpdated = null;

window.addEventListener("DOMContentLoaded", async () => {
  try {
    const res = await fetch("/me", {
      method: "GET",
      credentials: "include",
    });
    const result = await res.json();
    console.log(result);
    if (result.success && result.loggedIn) {
      loggedInEmail = result.email;
      document.getElementById(
        "welcome"
      ).textContent = `Welcome back, ${result.name}!`;
    }
  } catch (err) {}
  updateUI();
});

document.getElementById("loginForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;
  const loginMessage = document.getElementById("loginMessage");
  const welcome = document.getElementById("welcome");

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const result = await res.json();
    if (result.success) {
      loggedInEmail = email;
      loginMessage.textContent = loginMessage.textContent = result.message;
      loginMessage.style.color = "lightgreen";
      loginMessage.classList.remove("hidden");
      welcome.textContent = `Welcome back, ${result.username}!`;
      welcome.classList.remove("hidden");
      updateUI();
    } else {
      loginMessage.textContent = result.message || result.error;
      loginMessage.style.color = "red";
      loginMessage.classList.remove("hidden");
    }
  } catch (error) {
    loginMessage.textContent = error.message;
    loginMessage.style.color = "red";
    loginMessage.classList.remove("hidden");
  }
});

document.getElementById("createForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const createMessage = document.getElementById("createMessage");
  const name = document.getElementById("createName").value.trim();
  const nameIsValid = /^[a-zA_Z0-9]+$/.test(name);
  if (!nameIsValid) {
    createMessage.textContent = "Name must be alphanumeric only.";
    createMessage.style.color = "red";
    createMessage.classList.remove("hidden");
    return;
  }
  const email = document.getElementById("createEmail").value;
  const emailIsValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  if (!emailIsValid) {
    createMessage.textContent = "Email formatted incorectly.";
    createMessage.style.color = "red";
    createMessage.classList.remove("hidden");
    return;
  }
  const password = document.getElementById("createPassword").value;
  const isStrongPassword =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/.test(password);
  if (!isStrongPassword) {
    createMessage.textContent =
      "Strong password must be at least 8 characters and contain: one lowercase letter, one uppercase letter, one digit, one special character.";
    createMessage.style.color = "red";
    createMessage.classList.remove("hidden");
    return;
  }

  const res = await fetch("users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });

  const result = await res.json();
  createMessage.textContent = result.success
    ? "Account created!"
    : result.error;
  createMessage.style.color = result.success ? "lightgreen" : "red";
  createMessage.classList.remove("hidden");
  if (result.success) {
    document.getElementById("createForm").reset();
  }
});

document.getElementById("changePasswordBtn").addEventListener("click", () => {
  document.getElementById("changePasswordBox").classList.remove("hidden");
  document.getElementById("changePasswordForm").classList.remove("hidden");
});

document
  .getElementById("changePasswordForm")
  .addEventListener("submit", async (e) => {
    e.preventDefault();
    const oldPassword = document.getElementById("oldPassword").value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmPassword = document.getElementById("confirmPassword").value;
    const changePasswordMessage = document.getElementById(
      "changePasswordMessage"
    );

    const strongPasswordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$/;

    if (!strongPasswordRegex.test(newPassword)) {
      changePasswordMessage.textContent =
        "Password must be at least 8 characters, include uppercase, lowercase, number, and special character.";
      changePasswordMessage.style.color = "red";
      changePasswordMessage.classList.remove("hidden");
      return;
    }

    if (newPassword !== confirmPassword) {
      changePasswordMessage.textContent =
        "New password and confirm password do not match.";
      changePasswordMessage.style.color = "red";
      changePasswordMessage.classList.remove("hidden");
      return;
    }
    try {
      const res = await fetch(`users/${loggedInEmail}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ oldPassword, newPassword, confirmPassword }),
      });

      const result = await res.json();
      changePasswordMessage.textContent = result.success
        ? "Password change successful"
        : result.error;
      changePasswordMessage.style.color = result.success ? "lightgreen" : "red";
      changePasswordMessage.classList.remove("hidden");
      if (result.success) {
        passwordUpdated = true;
        updateUI();
      }
    } catch (err) {
      changePasswordMessage.textContent = "Something went wrong";
      changePasswordMessage.style.color = "red";
      changePasswordMessage.classList.remove("hidden");
    }
  });

document.getElementById("logoutBtn").addEventListener("click", async () => {
  try {
    const res = await fetch("/logout", {
      method: "POST",
      credentials: "include",
    });
    const result = await res.json();
    console.log(result);
    if (result.success) {
      loggedInEmail = null;
      document.getElementById("loginForm").reset();
      const message = document.getElementById("loginMessage");
      message.textContent = "Logged Out";
      message.style.color = "gray";
      message.classList.remove("hidden");
      updateUI();
    }
  } catch (err) {
    console.log("something went wrong in logout");
  }
});

function updateUI() {
  const show = (el) => el.classList.remove("hidden");
  const hide = (el) => el.classList.add("hidden");

  const welcome = document.getElementById("welcome");
  const loginForm = document.getElementById("loginForm");
  const logoutBtn = document.getElementById("logoutBtn");
  const createForm = document.getElementById("createBox");
  const createMessage = document.getElementById("createMessage");
  const changePasswordBtn = document.getElementById("changePasswordBtn");
  const changePasswordForm = document.getElementById("changePasswordForm");
  const changePasswordMessage = document.getElementById(
    "changePasswordMessage"
  );
  const loginMessage = document.getElementById("loginMessage");
  if (loggedInEmail) {
    hide(loginForm);
    hide(createForm);
    hide(createMessage);
    createMessage.textContent = "";
    show(logoutBtn);
    show(welcome);
    show(changePasswordBtn);
    show(loginMessage);

    if (passwordUpdated) {
      changePasswordForm.reset();
      hide(changePasswordForm);
      passwordUpdated = false;
    }
  } else {
    // hide(loginMessage)
    // loginMessage.textContent = "";
    show(loginForm);
    show(createForm);
    hide(logoutBtn);
    hide(changePasswordForm);
    hide(changePasswordMessage);
    changePasswordMessage.textContent = "";
    hide(welcome);
    welcome.textContent = "";
    hide(changePasswordBtn);
    show(createMessage);
  }
}
