require("dotenv").config();
const createError = require("http-errors");
const jwt = require("jsonwebtoken");

const verifyRefreshToken = (refreshToken) =>{
  jwt.verify(refreshToken,process.env.REFRESH_TOKEN_SECRET,(error,payload) => {
    if(error)
    {
        next(createError.Unauthorized());
        const userId = payload.id;
        return userId;
    }
  })
}