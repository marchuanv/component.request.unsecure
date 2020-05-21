const utils = require("utils");
const logging = require("logging");
const crypto = require("crypto");
const requestDeferred = require("component.request.deferred");
const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

logging.config.add("Sending Secure Request");

const isBase64String = (str) => {
    base64.lastIndex = 0;
    return base64.test(str);
};

const genRandomString = (length) => {
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};

const sha512 = (password, salt) => {
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    return { salt, hashedPassphrase: value };
};

const hashPassphrase = (userpassword, salt) => {
    salt = salt || genRandomString(16); /** Gives us salt of length 16 */
    return sha512(userpassword, salt);
}

const isExpiredSession = (expireDate) => {
    const currentDate = new Date();
    const expired = currentDate.getTime() > expireDate.getTime();
    return expired
}

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

function SecureSession({ username, hashedPassphrase, hashedPassphraseSalt, token, fromhost, fromport }) {
    
    this.id = utils.generateGUID();
    const { publicKey, privateKey } = generateKeys(hashedPassphrase);
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.encryptedPassphrase = encryptToBase64Str(hashedPassphrase,  this.publicKey);
    this.token = token || encryptToBase64Str(utils.getJSONString({ username , fromhost, fromport }), this.publicKey);
    this.fromhost =fromhost;
    this.fromport =fromport;

    this.authenticate = ({ passphrase }) => {
        const results = hashPassphrase(passphrase, hashedPassphraseSalt);
        return results.hashedPassphrase === hashedPassphrase;
    };

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
    hashPassphrase,
    send: async ({ host, port, path, method, headers, data }) => {
        const requestUrl = `${host}:${port}${path}`;
        const { username, passphrase, encryptionkey, token, fromhost, fromport } = headers;
        let session = module.exports.sessions.find(session => session.token === token);
        let encryptData = "";
        if (session){
            logging.write("Sending Secure Request",`using existing session ${session.id} for ${requestUrl}`);
            logging.write("Sending Secure Request",`encrypting data to send to ${requestUrl}`);
            encryptData = session.encryptData({ encryptionkey, data });
            headers.token = session.token;
            headers.encryptionkey = session.getEncryptionKey();
        } else if (username && passphrase) {
            const { hashedPassphrase, salt } = hashPassphrase(passphrase);
            session = new SecureSession({ username, hashedPassphrase, hashedPassphraseSalt: salt, token, fromhost, fromport });
            module.exports.sessions.push(session);
            encryptData = data;
            logging.write("Sending Secure Request",`creating new session ${session.id} for ${requestUrl}`);
            headers.token = session.token;
            headers.encryptionkey = session.getEncryptionKey();
        }
        const results = await requestDeferred.send({  host, port, path, method, headers, data: encryptData });
        if (session && results.statusCode === 200){
            logging.write("Sending Secure Request",`decrypting data received from ${requestUrl}`);
            if (isBase64String(results.data)===true){
                results.data = session.decryptData({ data: results.data });
            } else {
                logging.write("Sending Secure Request",`decryption failed, data received from ${requestUrl} is not encrypted.`);
            }
        }
        return results;
    }
};