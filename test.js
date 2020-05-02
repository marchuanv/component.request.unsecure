const componentRequestSecure = require("./component.request.secure.js");
const logging = require("logging");
logging.config(["Sending Secured Request", "Re-Sending Deferred Request", "Sending Request"]);
(async()=>{

    await componentRequestSecure.send({
        host: "localhost", 
        port: 5000, 
        path: "/test", 
        method:"POST", 
        headers: { 
            "Content-Type":"text/plain", 
            username: "admin1", 
            passphrase: "secure1",
            fromhost: "localhost",
            fromport: 6000
        }, 
        data: "Hello World From Client" 
    });

    await componentRequestSecure.send({
        host: "localhost", 
        port: 5000, 
        path: "/test", 
        method:"POST", 
        headers: { 
            "Content-Type":"text/plain", 
            username: "admin1", 
            passphrase: "secure1",
            fromhost: "localhost",
            fromport: 6000
        }, 
        data: "Hello World From Client" 
    });
    
})().catch((err)=>{
    console.log(err);
});
