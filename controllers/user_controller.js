const { findByIdAndUpdate } = require("../models/userModel");
const User = require("../models/userModel");
const appError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");

exports.getAllUsers = catchAsync(async (req, res, next) => {
  const users = await User.find();

  res.status(200).send({
    status: "success",
    length: users.length,
    users,
  });
});

exports.updateMe = catchAsync(async (req, res, next) => {
  if (Object.keys(req.body).length == 0)
    return next(new appError("There is nothing to update", 401));

  const { name, email } = req.body; //only update name and email

  // get the user and update it
  const user = await User.findByIdAndUpdate(
    { _id: req.user.id },
    { name, email },
    { new: true, runValidators: true }
  );

  // send the response
  res.status(200).send({
    status: "success",
    user,
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndUpdate(
    { _id: req.user.id },
    { active: false }
  );
  res.status(200).send();
});
