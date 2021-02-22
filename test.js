const unsecureRequest = require("./component.request.unsecure.js");
(async()=>{
    const results = await unsecureRequest.send({
        host: "localhost",
        port: 5000,
        path: "/test",
        method:"POST",
        headers: {
            "Content-Type":"text/plain",
            username: "admin1",
            fromhost: "localhost",
            fromport: 6000
        },
        data: "Hello World From Client"
    });
    if (results.statusCode !== 500){
        throw new Error("Test Failed");
    }

})().catch((err)=>{
    console.log(err);
});
