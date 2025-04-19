require("dotenv").config();
const mysql = require("mysql2");

const pool = mysql.createPool({
    host: process.env.HOST || "localhost",
    user:process.env.USERNAME || "root",
    password:process.env.PASSWORD || "Rithish@2006",
    database:process.env.DATABASE || "jwt",
    waitForConnections:true,
    connectionLimit:10,
    queueLimit:0
})

pool.getConnection((err, connection) => {
    if (err) {
      console.error("Error connecting to DB:", err);
    } else {
      console.log("DB connected successfully!");
      connection.release(); // release the connection back to the pool(after it performs a query it returns the connection back to the pool so this connection can be used for further queries)
    }
  });

module.exports = pool;