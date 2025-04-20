const express = require("express");
const router = express.Router();
const db = require("../db");
const validate = require("../utils/validator")
const createError = require("http-errors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const verifyRefreshToken = require("../utils/verifyRefreshToken");
const client = require("../utils/redis");
require("dotenv").config();

router.post("/auth/register",(req,res,next)=>{
    let {emailId,password} = req.body;
    try{
        if(!emailId || !password) throw createError.BadRequest(); // it throws the badrequest error and catched by catch block
        validate(emailId,password);
        let sql = "select * from users where emailId = ?";
        const values = [emailId];
        db.query(sql,values,async(error,result)=>{
            if(error) next(error);
            else if(result.length > 0) next(createError.Conflict(`${emailId} already exists!`));
            else{
                password = await bcrypt.hash(password,10);
                let insertsql = "INSERT INTO users (emailId, password) VALUES (?, ?);";
                db.query(insertsql,[emailId,password],async(error,result)=>{
                    if(error)next(error);
                    //generating jwt tokens
                    const accessToken = jwt.sign({id: result.insertId},process.env.ACCESS_TOKEN_SECRET,{expiresIn:"15m"});
                    const refreshToken = jwt.sign({id: result.insertId},process.env.REFRESH_TOKEN_SECRET,{expiresIn:"7d"});

                    // storing in redis cache system key -> userId, value -> newRefreshToken
                    try {
                        await client.set(result.insertId.toString(), refreshToken, {
                            EX: 604800 // 7 days
                        });
                    
                        res.status(200).json({
                            message: "user registered successfully!",
                            accessToken: accessToken,
                            refreshToken: refreshToken
                        });
                    } catch (redisError) {
                        console.log(redisError.message);
                        next(createError.InternalServerError());
                    }
                    
                   
                })
                
            }
        })
    }
    catch(error){
        next(error) //it sends the error to the global error handler
    }
})
router.post("/auth/login",(req,res,next)=>{
    const{emailId,password} = req.body;
    try{
        if(!emailId || !password) throw createError.BadRequest();
        validate(emailId,password);
        let sql = "select * from users where emailId = ?";
        const values = [req.body.emailId];
        db.query(sql,values,async(error,result)=>{
            if(error)next(error);
            else if(result.length == 0) return next(createError.Conflict('user not registered'));
            const isMatch = await bcrypt.compare(password,result[0].password);
            if (!isMatch) return next(createError.Unauthorized('Username/Password invalid'));
            // generating access token
            const accessToken = jwt.sign({id:result[0].id},process.env.ACCESS_TOKEN_SECRET,{expiresIn:"15m"})
            const refreshToken = jwt.sign({id:result[0].id},process.env.REFRESH_TOKEN_SECRET,{expiresIn:"7d"});

            // storing in redis cache system key -> userId, value -> newRefreshToken
            try {
                await client.set(result[0].id.toString(), refreshToken, {
                    EX: 604800 // 7 days
                });
            
                res.status(200).json({
                    message: "user registered successfully!",
                    accessToken: accessToken,
                    refreshToken: refreshToken
                });
            } catch (redisError) {
                console.log(redisError.message);
                next(createError.InternalServerError());
            }            
        })
    }
    catch(error){
        next(error);
    }
})
router.post("/auth/refresh-token", (req, res, next) => {
    const { refreshToken } = req.body;
    try {
        if (!refreshToken) return next(createError.BadRequest());

        // Passing the callback to handle the result of token verification
        verifyRefreshToken(refreshToken, async(error, userId) => { // this callback will return the userId if the refreshToken matches the refreshToken in redis
            if (error) {
                return next(error); // i have written the complete logic inside this callback function because if wrote the logic out of this callback before userId is returned the newTokens will be generated which will create problems 
            }

            // Now that we have the userId, we can generate new tokens
            const newAccessToken = jwt.sign({ id: userId }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "15m" });
            const newRefreshToken = jwt.sign({ id: userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });

            try {
                // Store the new refresh token in Redis
                await client.set(userId.toString(), newRefreshToken, {
                    EX: 604800 // 7 days
                }); 

                // Send the new tokens as response
                res.status(200).json({
                    message: "Refresh token successfully refreshed!",
                    newAccessToken: newAccessToken,
                    newRefreshToken: newRefreshToken
                });
            }
            catch (redisError) {
                console.log(redisError.message);
                return next(createError.InternalServerError());
            }});
            } catch (error) {
                next(error);
            }
        });

router.delete("/auth/logout",(req,res)=>{
    res.send("logout");
})

module.exports = router;