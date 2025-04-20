const redis = require("redis");
const client = redis.createClient({ //creates a connection between our server and redis server
    host: '172.30.147.70', // WSL's IP address became i downloaded it on ubunto, so its server will be running on ubunto's ip address
    port: 6379,        // Default Redis port
})

client.on('connect',() => { // works like addEventListener in js
    console.log("client connected to redis...")
})

client.on('error',(error) => {
    console.log(error.message)
})

client.on('ready',() => {
    console.log("Client connected to redis and ready to use...")
})

client.on('end',() => {
    console.log("client disconnected from redis")
})

process.on('SIGINT',() => { //connection will be ended when ctrl + C is pressed
    client.quit()
})

// THIS is important:
client.connect(); // <- this starts the actual connection!

module.exports = client;