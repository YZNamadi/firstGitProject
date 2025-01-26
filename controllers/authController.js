const jwt = require('jsonwebtoken');
const {
  signupSchema,
  signinSchema,
  acceptCodeSchema,
  changePasswordSchema,
  acceptFPCodeSchema,
} = require('../middlewares/validator');
const User = require('../models/usersModel');
const { doHash, doHashValidation, hmacProcess } = require('../utils/hashing');
const transport = require('../middlewares/sendMail');

// Signup Controller
exports.signup = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { error } = signupSchema.validate({ email, password });
    if (error) {
      return res.status(400).json({ 
        success: false, 
        message: error.details[0].message 
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        success: false, 
        message: 'User already exists!' 
      });
    }

    const hashedPassword = await doHash(password, 12);
    const newUser = await User.create({
      email,
      password: hashedPassword,
    });
    
    newUser.password = undefined;
    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      user: newUser,
    });
  } catch (error) {
    console.error('Signup Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

// Signin Controller
exports.signin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const { error } = signinSchema.validate({ email, password });
    if (error) {
      return res.status(400).json({ 
        success: false, 
        message: error.details[0].message 
      });
    }

    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    const validPassword = await doHashValidation(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid credentials' 
      });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email,
        verified: user.verified,
      },
      process.env.TOKEN_SECRET,
      { expiresIn: '8h' }
    );

    res
      .cookie('Authorization', `Bearer ${token}`, {
        expires: new Date(Date.now() + 8 * 3600000),
        httpOnly: process.env.NODE_ENV === 'production',
        secure: process.env.NODE_ENV === 'production',
      })
      .json({
        success: true,
        message: 'Login successful',
        token,
      });
  } catch (error) {
    console.error('Signin Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

// Signout Controller
exports.signout = async (req, res) => {
  try {
    res.clearCookie('Authorization');
    res.status(200).json({ 
      success: true, 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Signout Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

// Send Verification Code
exports.sendVerificationCode = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: email,
      subject: 'Verification Code',
      html: `<h1>${code}</h1>`,
    });

    user.verificationCode = hmacProcess(code, process.env.HMAC_VERIFICATION_CODE_SECRET);
    user.verificationCodeValidation = Date.now();
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'Verification code sent' 
    });
  } catch (error) {
    console.error('Send Verification Code Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send verification code' 
    });
  }
};

// Verify Verification Code
exports.verifyVerificationCode = async (req, res) => {
  const { email, providedCode } = req.body;
  try {
    const { error } = acceptCodeSchema.validate({ email, providedCode });
    if (error) {
      return res.status(400).json({ 
        success: false, 
        message: error.details[0].message 
      });
    }

    const user = await User.findOne({ email }).select('+verificationCode +verificationCodeValidation');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    if (Date.now() - user.verificationCodeValidation > 5 * 60 * 1000) {
      return res.status(400).json({ 
        success: false, 
        message: 'Verification code expired' 
      });
    }

    const hashedCode = hmacProcess(providedCode.toString(), process.env.HMAC_VERIFICATION_CODE_SECRET);
    if (hashedCode !== user.verificationCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid code' 
      });
    }

    user.verified = true;
    user.verificationCode = undefined;
    user.verificationCodeValidation = undefined;
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'Account verified successfully' 
    });
  } catch (error) {
    console.error('Verify Verification Code Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

// Change Password
exports.changePassword = async (req, res) => {
  const { userId } = req.user;
  const { oldPassword, newPassword } = req.body;

  try {
    const { error } = changePasswordSchema.validate({ oldPassword, newPassword });
    if (error) {
      return res.status(400).json({ 
        success: false, 
        message: error.details[0].message 
      });
    }

    const user = await User.findById(userId).select('+password');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const validPassword = await doHashValidation(oldPassword, user.password);
    if (!validPassword) {
      return res.status(401).json({ 
        success: false, 
        message: 'Invalid current password' 
      });
    }

    user.password = await doHash(newPassword, 12);
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'Password updated successfully' 
    });
  } catch (error) {
    console.error('Change Password Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};

// Send Forgot Password Code
exports.sendForgotPasswordCode = async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await transport.sendMail({
      from: process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
      to: email,
      subject: 'Password Reset Code',
      html: `<h1>${code}</h1>`,
    });

    user.forgotPasswordCode = hmacProcess(code, process.env.HMAC_VERIFICATION_CODE_SECRET);
    user.passwordResetCodeValidation = Date.now();
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'Password reset code sent' 
    });
  } catch (error) {
    console.error('Send Forgot Password Code Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to send reset code' 
    });
  }
};

// Verify Forgot Password Code
exports.verifyForgotPasswordCode = async (req, res) => {
  const { email, providedCode, newPassword } = req.body;
  try {
    const { error } = acceptFPCodeSchema.validate({ email, providedCode, newPassword });
    if (error) {
      return res.status(400).json({ 
        success: false, 
        message: error.details[0].message 
      });
    }

    const user = await User.findOne({ email }).select('+forgotPasswordCode +passwordResetCodeValidation');
    if (!user) {
      return res.status(404).json({ 
        success: false, 
        message: 'User not found' 
      });
    }

    if (!user.forgotPasswordCode || !user.passwordResetCodeValidation) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid reset code' 
      });
    }

    if (Date.now() - user.passwordResetCodeValidation > 5 * 60 * 1000) {
      return res.status(400).json({ 
        success: false, 
        message: 'Reset code expired' 
      });
    }

    const hashedCode = hmacProcess(providedCode.toString(), process.env.HMAC_VERIFICATION_CODE_SECRET);
    if (hashedCode !== user.forgotPasswordCode) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid reset code' 
      });
    }

    user.password = await doHash(newPassword, 12);
    user.forgotPasswordCode = undefined;
    user.passwordResetCodeValidation = undefined;
    await user.save();

    res.status(200).json({ 
      success: true, 
      message: 'Password reset successful' 
    });
  } catch (error) {
    console.error('Verify Forgot Password Error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error' 
    });
  }
};