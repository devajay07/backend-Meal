const express = require("express");
const authController = require("../controllers/auth_controller");
const userController = require("../controllers/user_controller");

const router = express.Router();

router.route("/signup").post(authController.signUp);
router.route("/login").post(authController.login);

router.route("/forgotPassword").post(authController.forgotPassword);
router.route("/resetPassword/:token").patch(authController.resetPassword);

router
  .route("/updatePassword")
  .patch(authController.protect, authController.updatePassword);

router
  .route("/updateMe")
  .patch(authController.protect, userController.updateMe);
router
  .route("/deleteMe")
  .delete(authController.protect, userController.deleteMe);

router.route("/").get(authController.protect, userController.getAllUsers);

module.exports = router;
