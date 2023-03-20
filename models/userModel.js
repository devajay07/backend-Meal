const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = mongoose.Schema({
  name: {
    type: String,
    trim: true,
    required: [true, "Please Tell us Your Name!"],
  },
  email: {
    type: String,
    trim: true,
    unique: [true, "This email is already in use"],
    required: [true, "You need to tell us your email"],
    validate: [validator.isEmail, "Not a valid email address!"],
  },
  photo: {
    type: String,
    trim: true,
  },
  role: {
    type: String,
    enum: ["user", "admin", "manager"],
    default: "user",
  },
  password: {
    type: String,
    trim: true,
    required: true,
    minlength: 6,
  },
  confirmPassword: {
    type: String,
    trim: true,
    required: [true, "You need to confirm your password"],
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: "Both Passwords are not same",
    },
  },
  changedPasswordAt: {
    type: Date,
  },
  passwordResetToken: {
    type: String,
  },
  resetTokenExpiresIn: {
    type: Date,
  },
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.confirmPassword = undefined;
});

userSchema.pre(/^find/, function (next) {
  this.find({ active: { $ne: false } });
  next();
});

userSchema.methods.createResetToken = function () {
  // generate a random token
  const resetToken = crypto.randomBytes(20).toString("hex");

  // encrypt it and save it in database
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");
  console.log(this.passwordResetToken);

  this.resetTokenExpiresIn = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

const userModel = mongoose.model("users", userSchema);

module.exports = userModel;
