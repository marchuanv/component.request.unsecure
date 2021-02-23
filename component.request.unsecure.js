const logging = require("logging");
const requestDeferred = require("component.request.deferred");
logging.config.add("Sending Unsecure Request");
module.exports = { 
    send: async ({ host, port, path, method, username, fromhost, fromport, data }) => {
        const requestUrl = `${host}:${port}${path}`;
        logging.write("Sending Unsecure Request",`sending unsecured request to ${requestUrl}`);
        return await requestDeferred.send({ host, port, path, method, headers: { username, fromhost, fromport }, data });
    }
};