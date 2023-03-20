const express = require("express");
const User = require("../models/userModel");
const appError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const bcrypt = require("bcryptjs/dist/bcrypt");
const sendEmail = require("../utils/email");
const { resolveObjectURL } = require("buffer");
const crypto = require("crypto");

const signJwt = (id) => {
  const token = jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
  return token;
};

function createSendToken(user, statusCode, res) {
  const token = signJwt(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };

  if (process.env.nodeEnv === "production") cookieOptions.secure = true;

  res.cookie("jwt", token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
}
exports.signUp = catchAsync(async (req, res, next) => {
  const user = await User.create({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    confirmPassword: req.body.confirmPassword,
  });

  createSendToken(user, 201, res);
});

exports.login = catchAsync(async (req, res, next) => {
  //grab email and password from body

  const email = req.body.email;
  const password = req.body.password;

  // check if email and password exits

  if (!email || !password)
    return next(new appError("Both fields are required!"), 401);

  // check if user in in database

  const user = await User.findOne({ email });
  if (!user) return next(new appError("No User found!"), 401);

  // check if password is correct

  bcrypt.compare(password, user.password, function (err, result) {
    if (err) return next(new appError(err.message, err.status));

    if (result) {
      createSendToken(user, 200, res);
    } else {
      return next(new appError("Incorrect Password", 201));
    }
  });
});

exports.protect = catchAsync(async (req, res, next) => {
  // get token from header
  let token = req.headers.authorization;

  // check wheather token even exists and starts with bearer in the request
  if (!token || !token.startsWith("Bearer"))
    return next(new appError("To access this route, please login first", 401));

  // verify token
  token = token.split(" ")[1];
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  // check if user exists at the time of request
  const VerifiedUser = await User.findOne({ _id: decoded.id });
  if (!VerifiedUser)
    return next(new appError("User does not exist, login again!", 401));

  // check if user has changed password
  if (VerifiedUser.changedPasswordAt) {
    const issuedTime = decoded.iat;
    const changedTime = VerifiedUser.changedPasswordAt.getTime();
    if (changedTime > issuedTime)
      return next(
        new appError("User has changed the password, please login again!")
      );
  }

  // give access to the protected route
  req.user = VerifiedUser;
  next();
});

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role))
      return next(new appError("You are not authorized to this action", 403));

    next();
  };
};

exports.forgotPassword = catchAsync(async (req, res, next) => {
  // get user email from the request
  const email = req.body.email;
  if (!email) return next(new appError("You need to provide your email!", 400));

  // get user from the email
  const user = await User.findOne({ email });
  if (!user) return next(new appError("No user found with this email!", 404));

  // get the generated token
  const resetToken = user.createResetToken();
  console.log(resetToken);
  await user.save({ validateBeforeSave: false });

  // send the unencrypted token through mail

  const resetUrl = `${req.protocol}://${req.get(
    "host"
  )}/api/v1/users/resetPassword/${resetToken}`;

  await sendEmail({
    email: user.email,
    subject: "Reset Your MealMate Password (valid for 10 mins)",
    text: resetUrl,
  });

  // send some response back
  res.status(200).send({
    status: "success",
    message: "reset link sent to mail!",
  });
});

exports.resetPassword = catchAsync(async (req, res, next) => {
  // get the token from params
  const resetToken = req.params.token;

  // find the user and verfiy the token
  const encToken = crypto.createHash("sha256").update(resetToken).digest("hex");

  const user = await User.findOne({
    passwordResetToken: encToken,
    resetTokenExpiresIn: { $gt: Date.now() },
  });

  if (!user) return next(new appError("Token is invalid or has expired", 401));

  // update the password and save it in database
  user.password = req.body.password;
  user.confirmPassword = req.body.confirmPassword;
  user.passwordResetToken = undefined;
  user.resetTokenExpiresIn = undefined;
  await user.save();
  // update changedPasswordAt property
  // send the token to the user
  createSendToken(user, 200, res);
});

exports.updatePassword = catchAsync(async (req, res, next) => {
  // get user from collection
  const user = await User.findById({ _id: req.user.id });
  if (!user) return next(new appError("You are not logged in!", 401));

  // check if posted password is correct
  bcrypt.compare(req.body.password, user.password, function (err, result) {
    if (err) return next(new appError(err.message, err.status));

    if (!result) {
      return next(new appError("Incorrect Password", 201));
    }
  });

  // update password
  user.password = req.body.newPassword;
  user.confirmPassword = req.body.confirmPassword;

  await user.save();

  // log in and send the token

  createSendToken(user, 200, res);
});
