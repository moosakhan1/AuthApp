const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: String,
  email: String,
  password: String,
  age: Number,
});

module.exports = mongoose.model("User", userSchema);
