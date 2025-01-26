const express = require('express');
const authController = require('../controllers/authController');
const { identifier } = require('../middlewares/identification');
const router = express.Router();

// Authentication routes
router.post('/signup', authController.signup);
router.post('/signin', authController.signin);
router.post('/signout', identifier, authController.signout);

// Verification routes
router.patch(
  '/send-verification-code',
  identifier,
  authController.sendVerificationCode
);
router.patch(
  '/verify-verification-code',
  identifier,
  authController.verifyVerificationCode // Fixed function name
);
router.patch('/change-password', identifier, authController.changePassword);

// Password recovery routes
router.patch(
  '/send-forgot-password-code',
  authController.sendForgotPasswordCode
);
router.patch(
  '/verify-forgot-password-code',
  authController.verifyForgotPasswordCode // Ensure this exists in controller
);

module.exports = router;