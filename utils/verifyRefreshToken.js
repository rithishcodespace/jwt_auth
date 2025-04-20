require("dotenv").config();
const createError = require("http-errors");
const jwt = require("jsonwebtoken");
const client = require("./redis");

// You're returning values from async callbacks, but that doesn’t return from the parent function.

// Instead, you should use a callback pattern, passing a function like callback(error, result).

const verifyRefreshToken = (refreshToken, callback) => {
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, payload) => {
    if (err) return callback(createError.Unauthorized());

    const userId = payload.id;
    client.get(userId, (err, result) => {
      if (err) return callback(createError.InternalServerError());

      if (refreshToken === result) {
        return callback(null, userId);
      } else {
        return callback(createError.Unauthorized());
      }
    });
  });
};

module.exports = verifyRefreshToken;


