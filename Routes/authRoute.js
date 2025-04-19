const express = require("express");
const router = express.Router();
const db = require("../db");
const validate = require("../utils/validator")
const createError = require("http-errors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
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
                    // else res.send("user registered successfully!")
                })
                //generating jwt tokens
                const accessToken = jwt.sign({id: result.insertId},process.env.ACCESS_TOKEN_KEY,{expiresIn:"15m"});
                res.send("user registered successfully! "+accessToken);
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
        const values = [req.body.emailId,req.body.password];
        db.query(sql,values,async(error,result)=>{
            if(error)next(error);
            else if(result.length == 0) return next(createError.Conflict('user not registered'));
            const isMatch = await bcrypt.compare(password,result[0].password);
            if (!isMatch) return next(createError.Unauthorized('Username/Password invalid'));
            // generating access token
            const accessToken = jwt.sign({id:result[0].id},process.env.ACCESS_TOKEN_KEY,{expiresIn:"15m"})
            res.send("user loggedIn successfull "+accessToken);
        })
    }
    catch(error){
        next(error);
    }
})
router.post("/auth/refresh-token",(req,res)=>{
    res.send("refresh-token");
})
router.delete("/auth/logout",(req,res)=>{
    res.send("logout");
})

module.exports = router;