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
router.post("/auth/refresh-token", async (req, res, next) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) return next(createError.BadRequest("Refresh token is required"));
  
      const userId = await verifyRefreshToken(refreshToken); // this compares the refreshToken sent with the refreshToken present in redis if rF === r_rF it returns the userId, with this id we can create new tokens
  
      const newAccessToken = jwt.sign({ id: userId }, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "15m",
      });
  
      const newRefreshToken = jwt.sign({ id: userId }, process.env.REFRESH_TOKEN_SECRET, {
        expiresIn: "7d",
      });
  
      await client.set(userId.toString(), newRefreshToken, { EX: 604800 }); // 7 days
  
      res.status(200).json({
        message: "Refresh token successfully refreshed!",
        newAccessToken,
        newRefreshToken,
      });
    } catch (error) {
      next(error);
    }
  });
  
router.delete("/auth/logout", async (req, res, next) => {
    try {
        const { refreshToken } = req.body;
        if (!refreshToken) throw createError.BadRequest("Refresh token is required");
          
        const userId = await verifyRefreshToken(refreshToken);
        await client.del(userId); // deletes the refresh token in redis 
        res.status(200).send("User logged out successfully");
        }
        catch (error) {
            next(error);
        }
        });
                    

module.exports = router;