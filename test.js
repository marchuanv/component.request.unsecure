const SecureSession = require("./component.request.secure.js");
const logging = require("logging");
logging.config(["Component Secure"]);
(async()=>{

    const username = "admin";
    const secureSession = new SecureSession({  username, passphrase: "secure1" });
    ({ token, encryptionkey } = secureSession);
    if (token){
        encryptedData = secureSession.encryptRequest({ data: "Hello World From Client" });
        decryptedData = secureSession.decryptRequest({ data: encryptedData });
    }
    console.log(decryptedData);
    
})().catch((err)=>{
    console.log(err);
});
