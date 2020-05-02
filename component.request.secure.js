const utils = require("utils");
const logging = require("logging");
const crypto = require("crypto");
const base64 = /^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$/;

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

const sendSecureRequest = async ({ host, port, path, requestHeaders, data, callback }) => {
    const requestUrl = `${host}:${port}${path}`;
    let session = module.exports.request.secure.sessions.find(session => session.token === requestHeaders.token);
    let encryptData = "";
    if (session){
        logging.write("Component Request Secure",`using existing session ${session.id} for ${requestUrl}`);
        logging.write("Component Request Secure",`encrypting data to send to ${requestUrl}`);
        encryptData = session.encryptData({ encryptionkey: requestHeaders.encryptionkey, data });
        requestHeaders.token = session.token;
        requestHeaders.encryptionkey = session.getEncryptionKey();
    } else if (requestHeaders.username && requestHeaders.passphrase) {
        const { hashedPassphrase, salt } = hashPassphrase(requestHeaders.passphrase);
        session = new SecureSession({
            username: requestHeaders.username, 
            hashedPassphrase, 
            hashedPassphraseSalt: salt, 
            token: requestHeaders.token, 
            fromhost: requestHeaders.fromhost, 
            fromport: requestHeaders.fromport
        });
        module.exports.request.secure.sessions.push(session);
        encryptData = data;
        logging.write("Component Request Secure",`creating new session ${session.id} for ${requestUrl}`);
        requestHeaders.token = session.token;
        requestHeaders.encryptionkey = session.getEncryptionKey();
    }
    const results = await callback({ requestHeaders, data: encryptData });
    if (session && results.statusCode === 200){
        logging.write("Component Request Secure",`decrypting data received from ${requestUrl}`);
        if (isBase64String(results.data)===true){
            results.data = session.decryptData({ data: results.data });
        } else {
            logging.write("Component Request Secure",`decryption failed, data received from ${requestUrl} is not encrypted.`);
        }
    }
    return results;
};

module.exports = { 
    request: {
        secure: { 
            sessions: [],
            send: sendSecureRequest,
            hashPassphrase
        }
    }
};