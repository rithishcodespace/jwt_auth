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
        const values = [emailId,password];
        db.query(sql,values,async(error,result)=>{
            if(error) next(error);
            else if(result.length > 0) next(createError.Conflict(`${emailId} already exists!`));
            else{
                password = await bcrypt.hash(password,10);
                let insertsql = "INSERT INTO users (emailId, password) VALUES (?, ?);";
                db.query(insertsql,[emailId,password],(error,result)=>{
                    if(error)next(error);
                    //generating jwt tokens
                    const accessToken = jwt.sign({id: result.insertId},process.env.ACCESS_TOKEN_SECRET,{expiresIn:"15m"});
                    const refreshToken = jwt.sign({id: result.insertId},process.env.REFRESH_TOKEN_SECRET,{expiresIn:"7d"});
                    res.status(200).json({message:"user registered successfull!","accessToken":accessToken,"refreshToken":refreshToken})
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
            res.status(200).json({message:"user logged in successfull!","accessToken":accessToken,"refreshToken":refreshToken})
        })
    }
    catch(error){
        next(error);
    }
})
router.post("/auth/refresh-token",(req,res)=>{
    const{refreshToken} = req.body;
    try{
        if(!refreshToken)return next(createError.BadRequest());
        const userId = verifyRefreshToken(refreshToken); //returns the userId

        // creates new pair of access and refresh token
        const newAccessToken = jwt.sign({id:userId},process.env.ACCESS_TOKEN_SECRET,{expiresIn:"15m"});
        const newRefreshToken = jwt.sign({id:userId},process.env.ACCESS_REFRESH_SECRET,{expiresIn:"7d"});

        // storing in redis cache system key -> userId, value -> newRefreshToken
        client.SET(userId, newRefreshToken, (error,reply) => {
            if(error)
            {
                console.log(error.message);
                next(createError.InternalServerError());
                return;
            }
        })
        res.status(200).json({message:"user logged in successfull!","newAccessToken":newAccessToken,"newRefreshToken":newRefreshToken})
    }
    catch(error){
        next(error);
    }
})
router.delete("/auth/logout",(req,res)=>{
    res.send("logout");
})

module.exports = router;