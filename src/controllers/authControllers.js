const {
  registerUser,
  getUserById,
  loginUser,
  logoutUser,
  verifyUserEmailService,
  resendVerificationEmail,
  updateUser,
  updateUserAvatar,
  loginOrRegisterOAuthUser,
  refreshAccessToken,
  updateTheme,
} = require('../services/authServices');

const { validateUser } = require('../middlewares/validationMiddleware');
const { extractUserId } = require('../middlewares/extractUserId');
const Joi = require('joi');

const axios = require('axios');

// --- Register ---
exports.register = async (req, res, next) => {
  const { username, email, password } = req.body;
  try {
    const user = await registerUser(username, email, password);
    res.status(201).json({ user });
  } catch (error) {
    res.status(500).json({ message: error.message });
    next(error);
  }
};

// --- Login ---
exports.login = async (req, res) => {
  const { email, password } = req.body;
  const { error } = validateUser.validate(req.body);
  if (error) return res.status(400).json({ message: error.message });

  try {
    const user = await loginUser(email, password);
    res.status(200).json({ user });
  } catch (error) {
    res.status(401).json({ message: error.message });
  }
};

// --- Logout ---
exports.logout = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ message: 'Missing Authorization header' });

    const userId = extractUserId(authHeader);

    await logoutUser(userId);
    res.status(200).json({ message: 'Logged out successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
    next(error);
  }
};

// --- Get current user ---
exports.getCurrentUser = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ message: 'Missing Authorization header' });

    const userId = extractUserId(authHeader);
    const user = await getUserById(userId);
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: error.message });
    next(error);
  }
};

// --- Verify email ---
exports.verifyUserEmail = async (req, res) => {
  const { verificationToken } = req.params;
  try {
    await verifyUserEmailService(verificationToken);
    res.setHeader('Content-Type', 'text/html');
    return res.redirect(302, 'https://turbomatrixxxl.github.io/Marketing_App/');
  } catch (error) {
    res
      .status(404)
      .json({ message: 'Error verifying user', error: error.message });
  }
};

// --- Resend verification email ---
exports.handleResendVerificationEmail = async (req, res) => {
  const emailSchema = Joi.object({ email: Joi.string().email().required() });
  const { error } = emailSchema.validate(req.body);
  if (error) return res.status(400).json({ message: 'Email wrong written' });

  const { email } = req.body;
  try {
    const response = await resendVerificationEmail(email);
    return res.status(200).json(response);
  } catch (error) {
    if (error.message === 'User not found')
      return res.status(400).json({ message: 'User not found' });
    if (error.message === 'Verification has already been passed')
      return res.status(400).json({ message: error.message });
    return res.status(500).json({ message: 'Internal server error' });
  }
};

// --- Update user info ---
exports.updateUserInfo = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader)
      return res.status(401).json({ message: 'Missing Authorization header' });

    const userId = extractUserId(authHeader);
    const { username, email, password } = req.body;
    const updateFields = { username, email };
    if (password) updateFields.password = password; // hash in service

    const user = await updateUser(userId, updateFields);
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: error.message });
    next(error);
  }
};

// --- Update avatar ---
exports.updateUserAvatar = async (req, res) => {
  try {
    if (!req.file)
      return res.status(400).json({ message: 'No file to upload' });

    const cloudinaryUrl = req.file.path;
    const user = await updateUserAvatar(req.user._id, cloudinaryUrl);
    res.status(200).json({ user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};

// helper: fetch profile from FB Graph API
const fetchFacebookProfileByAccessToken = async (accessToken) => {
  if (!accessToken) return null;
  try {
    const url = `https://graph.facebook.com/me?fields=id,name,email,picture&access_token=${accessToken}`;
    const { data } = await axios.get(url);
    return {
      id: data.id,
      name: data.name,
      email: data.email || null,
      avatar: data.picture?.data?.url || null,
    };
  } catch (err) {
    console.warn(
      'FB Graph API fetch failed:',
      err?.response?.data || err.message
    );
    return null;
  }
};

// --- OAuth login/register ---
exports.oauthLogin = async (req, res) => {
  const { profile, provider, accessToken } = req.body;
  try {
    let finalProfile = profile || {};

    // dacă nu avem email sau ID corect, încercăm Graph API cu accessToken
    if ((!finalProfile.email || !finalProfile.id) && accessToken) {
      const fetched = await fetchFacebookProfileByAccessToken(accessToken);
      if (fetched) {
        finalProfile = {
          id: fetched.id || finalProfile.id,
          name: fetched.name || finalProfile.name,
          email: fetched.email || finalProfile.email,
          avatar: fetched.avatar || finalProfile.avatar,
        };
      }
    }

    // Apelăm serviciul tău (ensure că acesta suportă profile fără email)
    const user = await loginOrRegisterOAuthUser(finalProfile, provider);

    // Verifică că generateTokens a populat token/refreshToken
    return res.status(200).json({ user });
  } catch (error) {
    console.error('oauthLogin error:', error);
    res.status(500).json({ message: error.message });
  }
};

// --- Refresh token ---
exports.refreshTokenController = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ message: 'Refresh token required' });

    const user = await refreshAccessToken(refreshToken);
    return res.status(200).json({ user });
  } catch (error) {
    return res.status(401).json({ message: error.message });
  }
};

// --- Update theme ---
exports.updateThemeController = async (req, res) => {
  try {
    // require authMiddleware on the route so req.user exists
    const userId = req.user && req.user._id;
    if (!userId) return res.status(401).json({ message: 'Not authorized' });

    const { theme } = req.body;
    if (!theme) return res.status(400).json({ message: 'Theme required' });

    if (theme !== 'light' && theme !== 'dark') {
      return res
        .status(400)
        .json({ message: 'Theme must be "dark" or "light" only' });
    }

    const user = await updateTheme(userId, theme);
    return res.status(200).json({ user });
  } catch (error) {
    return res.status(401).json({ message: error.message });
  }
};
