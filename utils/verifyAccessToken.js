require("dotenv").config();
const createError = require("http-errors");
const jwt = require("jsonwebtoken");

const verifyAccessToken = (req,res,next) => {
    if(!req.headers['authorization']) return next(createError.Unauthorized());
    const authHeader = req.headers['authorization']; // headers : {authorization : bearer your_Token}
    const bearer_Token = authHeader.split(' '); // splits bearer and token with space(' ')
    console.log(bearer_Token);
    const accessToken = bearer_Token[1]; // takes only token from the array
    jwt.verify(accessToken,process.env.ACCESS_TOKEN_SECRET,(error,payload)=>{
        if(error)
        {
            if(error.name === "JsonWebTokenError"){
                return next(createError.Unauthorized()); // handles errors like invalid signature, token malformed -> but here we should not sent the actual error -> so i used unauthorized error 
            }
            else{
                return next(error.message); // handles errors like token expired,etc..
            }
        } 
        req.payload = payload; //it attaches payload(id) to the next middleware
        next();
    })
}

module.exports = verifyAccessToken;