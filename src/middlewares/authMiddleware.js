/* eslint-disable no-undef */
const jwt = require('jsonwebtoken');
const User = require('../models/userSchema');
require('dotenv').config();

const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Not authorized' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // verificăm doar access token-ul
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ message: 'Not authorized' });
    }

    req.user = user;
    next();
  } catch (error) {
    // token expirat sau invalid
    return res.status(401).json({
      message: 'Not authorized or token expired',
      error: error.message,
    });
  }
};

module.exports = { authMiddleware };
