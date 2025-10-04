/* eslint-disable no-undef */
const User = require('../models/userSchema');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
require('dotenv').config();

const secret = process.env.JWT_SECRET;
const sendVerificationEmail = require('../utils/emailService');

// --- Helper pentru generare token ---
const generateTokens = async (user) => {
  if (!user.verify) return { token: null, refreshToken: null };

  const payload = { id: user._id, username: user.username, email: user.email };
  const token = jwt.sign(payload, secret, { expiresIn: '15m' });
  const refreshToken = crypto.randomBytes(64).toString('hex');

  user.token = token;
  user.refreshToken = {
    token: refreshToken,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 zile
  };

  await user.save();

  return { token, refreshToken };
};

// --- Register ---
const registerUser = async (username, email, password) => {
  const existingUser = await User.findOne({ email });
  if (existingUser) throw new Error('Email in use');

  // if sendVerificationEmail returns a token currently, keep using it;
  // otherwise it should send an email and return something (kept as-is to not touch front)
  const verificationToken = await sendVerificationEmail(email);

  const user = new User({
    username,
    email,
    password,
    verificationToken,
    // asigură inițializare pentru refreshToken ca obiect (opțional)
    refreshToken: { token: null, createdAt: null, expiresAt: null },
    token: null,
    theme,
    avatarURL,
    verify,
    providers,
  });

  user.setPassword(password);
  await user.save();

  // Return user cu token null, pentru că nu e verificat
  // sanitize dacă e cazul în controller (aici returnăm modelul mongoose)
  return user;
};

// --- Login ---
const loginUser = async (email, password) => {
  const user = await User.findOne({ email });
  if (!user || !user.validPassword(password)) {
    throw new Error('Email or password is wrong');
  }

  await generateTokens(user);
  return user;
};

// --- Get user by ID ---
const getUserById = async (userId) => {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');

  return user;
};

// --- Logout ---
const logoutUser = async (userId) => {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');

  user.token = null;
  user.refreshToken = { token: null, createdAt: null, expiresAt: null };
  await user.save();

  return user;
};

// --- Verify email ---
const verifyUserEmailService = async (verificationToken) => {
  const user = await User.findOne({ verificationToken });
  if (!user) throw new Error('Invalid or expired verification token');
  if (user.verify) throw new Error('Verification has already been passed');

  user.verify = true;
  user.verificationToken = null;
  await user.save();

  return user;
};

// --- Resend verification email ---
const resendVerificationEmail = async (email) => {
  const user = await User.findOne({ email });
  if (!user) throw new Error('User not found');
  if (user.verify) throw new Error('Verification has already been passed');

  const verificationToken = await sendVerificationEmail(user.email);
  user.verificationToken = verificationToken;
  await user.save();

  return { message: 'Verification email sent' };
};

// --- Update user ---
const updateUser = async (userId, fields) => {
  const user = await User.findById(userId);
  if (!user) throw new Error(`User with id ${userId} not exists!`);

  Object.assign(user, fields);
  if (fields.password) user.setPassword(fields.password);
  await user.save();

  return user;
};

// --- Update avatar ---
const updateUserAvatar = async (userId, avatarURL) => {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');

  user.avatarURL = avatarURL;
  await user.save();

  return user;
};

// --- OAuth login/register ---
const loginOrRegisterOAuthUser = async (profile, provider) => {
  const { email, name, avatar, id } = profile || {};

  if (!email) {
    throw new Error('Facebook login requires an email');
  }

  // 1) încercare după email (dacă există)
  let user = null;
  if (email) {
    user = await User.findOne({ email });
  }

  // 2) fallback: după provider id
  if (!user && id) {
    user = await User.findOne({
      'providers.name': provider,
      'providers.id': id,
    });
  }

  if (user) {
    // asigurăm existența provider entry (potrivirea pe id)
    const providerExists = Array.isArray(user.providers)
      ? user.providers.some((p) => p.name === provider && p.id === id)
      : false;

    if (!providerExists) {
      user.providers.push({ name: provider, id });
      await user.save();
    }

    // generateTokens va salva tokenurile pe user
    await generateTokens(user);

    const fresh = await User.findById(user._id).lean();
    return fresh;
  }

  // creare user nou (posibil fără email)
  const randomPassword = crypto.randomBytes(16).toString('hex');
  const newUser = new User({
    username: name || `user_${provider}_${id}`,
    email: email || null,
    password: randomPassword,
    avatarURL: avatar || null,
    verify: email ? true : false, // dacă ai email, marcăm verify true
    providers: id ? [{ name: provider, id }] : [],
    refreshToken: { token: null, createdAt: null, expiresAt: null },
    token: null,
    theme: 'light',
  });

  if (typeof newUser.setPassword === 'function') {
    newUser.setPassword(randomPassword);
  }

  await newUser.save();
  await generateTokens(newUser);

  const fresh = await User.findById(newUser._id).lean();
  return fresh;
};

// --- Refresh access token ---
const refreshAccessToken = async (refreshToken) => {
  if (!refreshToken) throw new Error('Refresh token required');

  // găsește userul după token-ul stocat în obiectul refreshToken
  const user = await User.findOne({ 'refreshToken.token': refreshToken });
  if (!user) throw new Error('Invalid refresh token');

  const stored = user.refreshToken;
  if (
    !stored ||
    !stored.token ||
    !stored.expiresAt ||
    new Date(stored.expiresAt) < new Date()
  ) {
    throw new Error('Refresh token expired');
  }

  const payload = { id: user._id, username: user.username, email: user.email };
  const token = jwt.sign(payload, secret, { expiresIn: '15m' });

  const newRefreshToken = crypto.randomBytes(64).toString('hex');
  user.refreshToken = {
    token: newRefreshToken,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
  };

  user.token = token;
  await user.save();

  return user;
};

const updateTheme = async (userId, theme) => {
  const user = await User.findById(userId);
  if (!user) throw new Error('User not found');

  user.theme = theme;
  await user.save();

  return user;
};

module.exports = {
  registerUser,
  loginUser,
  getUserById,
  logoutUser,
  verifyUserEmailService,
  resendVerificationEmail,
  updateUser,
  updateUserAvatar,
  loginOrRegisterOAuthUser,
  refreshAccessToken,
  updateTheme,
};
