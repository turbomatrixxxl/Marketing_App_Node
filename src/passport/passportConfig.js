/* eslint-disable no-undef */
// config/passport.js
const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;

const User = require('../models/userSchema');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET;

// --- JWT Strategy ---
const jwtOpts = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: JWT_SECRET,
};

passport.use(
  new JwtStrategy(jwtOpts, async (payload, done) => {
    try {
      const user = await User.findById(payload.id);
      if (!user) return done(null, false);
      return done(null, user);
    } catch (err) {
      return done(err, false);
    }
  })
);

// --- Google OAuth Strategy ---
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (_, __, profile, done) => {
      // accesToken și refreshToken ignorate
      try {
        const { id, displayName, emails, photos } = profile;
        const email = emails[0].value;
        const avatar = photos[0].value;

        let user = await User.findOne({ email });

        if (!user) {
          const randomPassword = require('crypto')
            .randomBytes(16)
            .toString('hex');
          user = new User({
            username: displayName,
            email,
            password: randomPassword,
            avatarURL: avatar,
            verify: true,
            providers: [{ name: 'google', id }],
          });
          user.setPassword(randomPassword);
          await user.save();
        } else {
          const providerEntry = user.providers.find((p) => p.name === 'google');
          if (!providerEntry) {
            user.providers.push({ name: 'google', id });
            await user.save();
          }
        }

        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

// --- Facebook OAuth Strategy ---
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ['id', 'displayName', 'emails', 'photos'],
    },
    async (_, __, profile, done) => {
      // accesToken și refreshToken ignorate
      try {
        const { id, displayName, emails, photos } = profile;
        const email = emails?.[0]?.value;
        const avatar = photos?.[0]?.value;

        if (!email) {
          return done(
            new Error('Facebook account has no email associated'),
            null
          );
        }

        let user = await User.findOne({ email });

        if (!user) {
          const randomPassword = require('crypto')
            .randomBytes(16)
            .toString('hex');
          user = new User({
            username: displayName,
            email,
            password: randomPassword,
            avatarURL: avatar,
            verify: true,
            providers: [{ name: 'facebook', id }],
          });
          user.setPassword(randomPassword);
          await user.save();
        } else {
          const providerEntry = user.providers.find(
            (p) => p.name === 'facebook'
          );
          if (!providerEntry) {
            user.providers.push({ name: 'facebook', id });
            await user.save();
          }
        }

        return done(null, user);
      } catch (err) {
        return done(err, false);
      }
    }
  )
);

// --- Serialize / Deserialize (opțional, pentru session) ---
passport.serializeUser((user, done) => done(null, user._id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

module.exports = passport;
