// Generate and sign key pair with defined key and salt
// Send public key to client
// Encrypt some data on backend
// Decrypt this data on client side using sjcl.js on the fly during read
const rxjs = require('rxjs');
const crypto = require('crypto');
const pem = require('pem');
const text = require('text-encoding');

// https://github.com/Dexus/pem/issues/58#issuecomment-121206356
/*pem.config({
    pathOpenSSL: 'C:\\cygwin64\\bin\\openssl'
});
*/

class CryptoService {

    constructor() {

        this.privateKey$ = rxjs.Observable.create(observer => {
            pem.createPrivateKey(2048, {'ciphers': ['aes256']}, (err, keyObj) => {
                if (err) {
                    console.log('Error creating private key: ', err);
                    observer.error(err);
                    return;
                }
                observer.next(keyObj.key);
                observer.complete();
            })
        }).publishReplay(1).refCount();

        this.publicKey$ = this.privateKey$.switchMap(key => rxjs.Observable.create(observer => pem.getPublicKey(key, (err, keyObj) => {
            if (err) {
                console.log('Error creating public key: ', err);
                observer.error(err);
                return;
            }
            observer.next(keyObj.publicKey);
            observer.complete();
        }))).publishReplay(1).refCount();

        this.modulus$ = this.privateKey$.switchMap(key => rxjs.Observable.create(observer => pem.getModulus(key, (err, modulusObj) => {
            if (err) {
                console.log('Error calculating modulus: ', err);
                observer.error(err);
                return;
            }
            observer.next(modulusObj.modulus);
            observer.complete();
        }))).publishReplay(1).refCount();
    }

    /**
     * Feed junks of max. 245 bytes.
     * @param plainText
     * @returns {*}
     */
    encrypt(plainText) {
        return this.publicKey$.map(key => {
            const keyBuff = new Buffer(key, 'utf-8');
            const dataBuff = new Buffer(plainText, 'utf-8');
            return crypto.publicEncrypt(keyBuff, dataBuff).toString('base64');
        });
    }

    decrypt(cipherText) {
        return this.privateKey$.zip(this.modulus$).map(([key, modulus]) => {
            let plainBuf = new Buffer(cipherText.length);
            let cipherBuf = new Buffer(cipherText, 'base64');
            for (let i = 0; i <= cipherBuf.length; i += modulus.length) {
                plainBuf = Buffer.concat([plainBuf, crypto.privateDecrypt(key, cipherBuf.slice(i, i + modulus.length))]);
            }
            return plainBuf.toString('utf-8');
        }).do(text => console.log('Encrypted: ' + text));
    }

    sign(data) {
        let signer = crypto.createSign('sha256');
        signer.update(data);
        return signer.sign(this.privateKey, 'base64');
    }

    verify(data, signature) {
        let verifier = crypto.createVerify('sha256');
        verifier.update(data);
        return verifier.verify(data, signature, 'base64')
    }
}

module.exports = new CryptoService();