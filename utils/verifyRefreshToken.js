require("dotenv").config();
const createError = require("http-errors");
const jwt = require("jsonwebtoken");
const client = require("./redis");

const verifyRefreshToken = async (refreshToken) => {
  try {
    const payload = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const userId = String(payload.id);
    const storedToken = await client.get(userId); // await promise

    if (refreshToken === storedToken) {
      return userId;
    } else {
      throw createError.Unauthorized("Token mismatch");
    }
  } catch (err) {
    throw createError.Unauthorized(err.message);
  }
};

module.exports = verifyRefreshToken;
