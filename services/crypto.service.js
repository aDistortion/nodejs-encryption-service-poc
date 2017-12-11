// Generate and sign key pair with defined key and salt
// Send public key to client
// Encrypt some data on backend
// Decrypt this data on client side using sjcl.js on the fly during read
const rxjs = require('rxjs');
const crypto = require('crypto');
const pem = require('pem');
const text = require('text-encoding');

// https://github.com/Dexus/pem/issues/58#issuecomment-121206356
pem.config({
    pathOpenSSL: 'C:\\cygwin64\\bin\\openssl'
});

const textEncoding = require('text-encoding');

class CryptoService {

    constructor(){

        this.privateKey$ = rxjs.Observable.create(observer => {
            pem.createPrivateKey(2048, {'ciphers': ['aes256']}, (err, keyObj) => {
                if(err){
                    console.log('Error creating private key: ', err);
                    observer.error(err);
                    return;
                }
                observer.next(keyObj.key);
                observer.complete();
            })
        }).publishReplay(1).refCount();

        this.publicKey$ = this.privateKey$.switchMap(key => rxjs.Observable.create(observer => pem.getPublicKey(key, (err, keyObj) => {
            if(err){
                console.log('Error creating public key: ',err);
                observer.error(err);
                return;
            }
            observer.next(keyObj.publicKey);
            observer.complete();
        }))).publishReplay(1).refCount();
    }

    encrypt(plainText){
        return this.publicKey$.map(key => {
            const keyBuff = new Buffer(key.toString());
            const dataBuff = new Buffer(plainText);
            return crypto.publicEncrypt(keyBuff, dataBuff).toString('base64');
        });
    }

    // error:0406506C:rsa routines:RSA_EAY_PRIVATE_DECRYPT:data greater than mod len
    decrypt(cipherText){
        return this.privateKey$.map(key => {
            return crypto.privateDecrypt(new Buffer(key), new Buffer(cipherText));
        }).do(console.log);
            //.map(buf => text.TextDecoder().decode(buf));
    }

    sign(data){
        let signer = crypto.createSign('sha256');
        signer.update(data);
        return signer.sign(this.privateKey, 'base64');
    }

    verify(data, signature){
        let verifier = crypto.createVerify('sha256');
        verifier.update(data);
        return verifier.verify(data, signature, 'base64')
    }
}

module.exports = new CryptoService();