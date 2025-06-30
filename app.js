const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");

const UserModel = require("./model/user");

const app = express();

mongoose
  .connect("mongodb://127.0.0.1:27017/authtestapp", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

app.set("view engine", "ejs");
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

function isAuthenticated(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.redirect("/login");
  jwt.verify(token, "shhhhhhhhhhhh", (err, decoded) => {
    if (err) return res.redirect("/login");
    req.user = decoded;
    next();
  });
}

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/create", (req, res) => {
  res.render("signup");
});

app.post("/create", (req, res) => {
  const { username, email, password, age } = req.body;
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      const createdUser = await UserModel.create({
        username,
        email,
        password: hash,
        age,
      });
      const token = jwt.sign({ email }, "shhhhhhhhhhhh");
      res.cookie("token", token);
      res.redirect("/dashboard");
    });
  });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  const user = await UserModel.findOne({ email: req.body.email });
  if (!user) return res.send("Invalid credentials");
  bcrypt.compare(req.body.password, user.password, (err, result) => {
    if (result) {
      const token = jwt.sign({ email: user.email }, "shhhhhhhhhhhh");
      res.cookie("token", token);
      res.redirect("/dashboard");
    } else {
      res.send("Invalid credentials");
    }
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  res.redirect("/");
});

app.get("/dashboard", isAuthenticated, async (req, res) => {
  const user = await UserModel.findOne({ email: req.user.email });
  res.render("dashboard", { user });
});

app.post("/update-password", isAuthenticated, async (req, res) => {
  const { newPassword } = req.body;
  const salt = await bcrypt.genSalt(10);
  const hash = await bcrypt.hash(newPassword, salt);
  await UserModel.findOneAndUpdate(
    { email: req.user.email },
    { password: hash }
  );
  res.redirect("/dashboard");
});

app.post("/update-email", isAuthenticated, async (req, res) => {
  const { newEmail } = req.body;
  await UserModel.findOneAndUpdate(
    { email: req.user.email },
    { email: newEmail }
  );
  const token = jwt.sign({ email: newEmail }, "shhhhhhhhhhhh");
  res.cookie("token", token);
  res.redirect("/dashboard");
});

app.post("/delete-account", isAuthenticated, async (req, res) => {
  await UserModel.findOneAndDelete({ email: req.user.email });
  res.clearCookie("token");
  res.redirect("/");
});

app.listen(3000, () => {
  console.log("🚀 Server is running on http://localhost:3000");
});
