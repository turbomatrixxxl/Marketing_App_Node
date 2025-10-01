/* eslint-disable no-undef */
const app = require('./app');
const mongoose = require('mongoose');
require('dotenv').config();

const PORT = process.env.PORT || 5000;
const uriDB = process.env.DB_URL;

// Evităm warning-uri Mongoose legate de strictQuery
mongoose.set('strictQuery', true);

mongoose
  .connect(uriDB)
  .then(() => {
    console.log('Connected to MongoDB successfully.');
    app.listen(PORT, () => {
      console.log(`Server running. Use our API on port: ${PORT}`);
    });
  })
  .catch((err) => {
    console.error(`Server not running. Error message: ${err.message}`);
    process.exit(1);
  });

// Optional: log errors pe parcursul rulării
mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});
