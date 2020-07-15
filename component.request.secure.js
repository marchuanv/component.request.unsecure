const utils = require("utils");
const crypto = require("crypto");
const requestDeferred = require("component.request.deferred");
const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

const logging = require("logging");
logging.config.add("Sending Secure Request");


const isBase64String = (str) => {
    base64.lastIndex = 0;
    return base64.test(str);
};

const stringToBase64 = (str) => {
    return Buffer.from(str, "utf8").toString("base64");
}

const base64ToString = (base64Str) => {
    return Buffer.from(base64Str, "base64").toString("utf8");;
}

const encryptToBase64Str = (dataStr, encryptionkey) => {
    const dataBuf = Buffer.from(dataStr, "utf8");
    return crypto.publicEncrypt( { 
        key: encryptionkey,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, dataBuf).toString("base64");
}

const decryptFromBase64Str = (base64Str, decryptionKey, passphrase) => {
    const dataBuf = Buffer.from(base64Str, "base64");
    return crypto.privateDecrypt({ 
        key: decryptionKey,
        passphrase,
        padding: crypto.constants.RSA_PKCS1_PADDING
    }, dataBuf).toString("utf8");
}

const generateKeys = (passphrase) => {
    return crypto.generateKeyPairSync('rsa', { modulusLength: 4096,
        publicKeyEncoding: { type: 'spki', format: 'pem'},
        privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase }
    });
};

function SecureSession({ username, port, fromhost, fromport, token, hashedPassphrase, hashedPassphraseSalt }) {
    
    this.id = utils.generateGUID();
    this.fromhost = fromhost;
    this.fromport = fromport;
    this.username = username;
    this.port = port;
    this.hashedPassphrase = hashedPassphrase;
    this.hashedPassphraseSalt = hashedPassphraseSalt;
    this.token = token;
    const { publicKey, privateKey } = generateKeys(hashedPassphrase);
    this.privateKey = privateKey;
    this.publicKey = publicKey;

    this.getEncryptionKey = () => {
        return stringToBase64(this.publicKey);
    };

    this.encryptData= ({ encryptionkey, data } ) => {
        const encryptedData = encryptToBase64Str(data, base64ToString(encryptionkey || "") || this.publicKey );
        return encryptedData;
    };
    
    this.decryptData = ({ data } ) => {
        const decryptedData = decryptFromBase64Str(data, this.privateKey, hashedPassphrase);
        return decryptedData;
    };
}

module.exports = { 
    sessions: [],
    send: async ({ host, port, path, method, headers: { username, passphrase, encryptionkey, token, hashedPassphrase, hashedPassphraseSalt, fromhost, fromport }, data }) => {
        const requestUrl = `${host}:${port}${path}`;
        let session = module.exports.sessions.find(s => s.token === token && s.port === port);
        if (session){
            logging.write("Sending Secure Request",`using existing session ${session.id} for ${requestUrl}`);
            logging.write("Sending Secure Request",`encrypting data to send to ${requestUrl}`);
            const encryptData = session.encryptData({ encryptionkey, data });
            encryptionkey = session.getEncryptionKey();
            ({ statusCode, data } = await requestDeferred.send({  host, port, path, method, headers: { username, encryptionkey, token, hashedPassphrase, hashedPassphraseSalt, fromhost, fromport }, data: encryptData }));
            if (statusCode === 200){
                logging.write("Sending Secure Request",`decrypting data received from ${requestUrl}`);
                if (isBase64String(data)===true){
                    data = session.decryptData({ data });
                } else {
                    logging.write("Sending Secure Request",`decryption failed, data received from ${requestUrl} is not encrypted.`);
                }
            }
            return { statusCode, data };
        } else if (username && passphrase) {
            ({ hashedPassphrase, hashedPassphraseSalt } = utils.hashPassphrase(passphrase));
            ({ headers: { token, encryptionkey } } = await requestDeferred.send({  host, port, path, method, headers: { username, hashedPassphrase, hashedPassphraseSalt, fromhost, fromport }, data: "fetching encryptionkey and token" }));
            logging.write("Sending Secure Request",`creating new session for ${requestUrl}`);
            session = new SecureSession({ username, port, hashedPassphrase, hashedPassphraseSalt, token, fromhost, fromport });
            module.exports.sessions.push(session);
            return await module.exports.send({ host, port, path, method, headers: { username, passphrase, encryptionkey, token, hashedPassphrase, hashedPassphraseSalt, fromhost, fromport }, data });
        } else if (username && hashedPassphrase && hashedPassphraseSalt){
            ({ headers: { token, encryptionkey } } = await requestDeferred.send({  host, port, path, method, headers: { username, hashedPassphrase, hashedPassphraseSalt, fromhost, fromport }, data: "fetching encryptionkey and token" }));
            logging.write("Sending Secure Request",`creating new session for ${requestUrl}`);
            session = new SecureSession({ username, port, hashedPassphrase, token, hashedPassphraseSalt, fromhost, fromport });
            module.exports.sessions.push(session);
            return await module.exports.send({ host, port, path, method, headers: { username, passphrase, encryptionkey, token, hashedPassphrase, hashedPassphraseSalt, fromhost, fromport }, data });
        }
    }
};