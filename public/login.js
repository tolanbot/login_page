window.addEventListener("DOMContentLoaded", updateUI);

let loggedInEmail = null;
let passwordUpdated = null;
console.log(`loggedInEmail: ${loggedInEmail}`);
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
      console.log(`loggedInEmail: ${loggedInEmail}`);
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
    loginMessage.textContent = "An error occurred";
    loginMessage.style.color = "red";
    loginMessage.classList.remove("hidden");
  }
});

document.getElementById("createForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const name = document.getElementById("createName").value;
  const email = document.getElementById("createEmail").value;
  const password = document.getElementById("createPassword").value;
  const msg = document.getElementById("createMessage");

  const res = await fetch("users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, email, password }),
  });

  const result = await res.json();
  msg.textContent = result.user ? "Account created!" : result.error;
  msg.style.color = result.success ? "lightgreen" : "red";
  msg.classList.remove("hidden");
  if (result.success) {
    document.getElementById("createForm").reset();
  }
});

document.getElementById("changePasswordBtn").addEventListener("click", () => {
  document.getElementById("changePasswordBox").classList.remove("hidden");
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
    try {
      console.log(`loggedInEmail: ${loggedInEmail}`);
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

document.getElementById("logoutBtn").addEventListener("click", () => {
  loggedInEmail = null;
  document.getElementById("loginForm").reset();
  const message = document.getElementById("loginMessage");
  message.textContent = "Logged Out";
  message.style.color = "gray";
  message.classList.remove("hidden");
  updateUI();
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
    hide(changePasswordMessage);
    changePasswordMessage.textContent = "";
    hide(welcome);
    welcome.textContent = "";
    hide(changePasswordBtn);
  }
}
