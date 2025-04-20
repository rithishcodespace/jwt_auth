require("dotenv");
const client = require("./utils/redis");
const express = require("express");
const app = express();
const cors = require("cors");
const morgan = require("morgan"); //log the request
const createError = require("http-errors"); //shows the https errors
const authRoute = require("./Routes/authRoute")
const PORT = process.env.PORT || 5000;
const verifyAccessToken = require("./utils/verifyAccessToken");

app.use(express.json());
app.use(cors());
app.use(morgan('dev')) //developement build
app.use(authRoute);

app.use("/",verifyAccessToken,(req,res)=>res.send("hello from express!"));

app.use((req,res,next)=>{ // This middleware catches any routes that are not matched by any previous routes and creates a "Not Found" error (404).
    next(createError.NotFound())
})
app.use((error,req,res,next)=>{ // This middleware is a global error handler. It's used to catch and handle any errors that occur throughout the app.
    res.status(error.status || 500)
    res.send({
        error:{
            status: error.status || 500,
            message: error.message
        }
    })
})

app.listen(PORT||5000,() => console.log(`server listening successfully on http://localhost:${PORT}`));
