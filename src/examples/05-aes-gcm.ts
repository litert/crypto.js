// tslint:disable: no-console

import * as $Crypto from "../lib";
import * as $fs from "fs";
import * as _ from "./Utils";

const PBKDF2_SALT = "@litert/crypto";
const PBKDF2_ITERATION = 100;

const DEMO_PASSPHRASE = "I am rock!";
const DEMO_PLAINTEXT = "hello world!fsafsafsafsafsf";
const DEMO_IV = Buffer.from("123414123213213121312");

const key = $Crypto.PBKDF2.createPBKDF2KeyGenerator({
    digestHasher: $Crypto.Hash.SHA256,
    salt: PBKDF2_SALT,
    iterations: PBKDF2_ITERATION,
}).createSync(DEMO_PASSPHRASE, {
    keyWidth: 128
});

const DEMO_AAD = Buffer.from("1");

const cipher = $Crypto.Ciphers.AES.GCM;

(() => {

    const result = cipher.encrypt(DEMO_PLAINTEXT, {
        key,
        iv: DEMO_IV
    });

    console.log(result.ciphertext.toString("hex"));

    console.log(cipher.decrypt(result.ciphertext, {
        key,
        iv: result.iv,
        authTag: result.authTag
    }).toString());

})();

(async () => {

    const SOURCE_PLAIN_FILE = "./test/random.bin";
    const SOURCE_PLAIN_FILE_SIZE = $fs.statSync(SOURCE_PLAIN_FILE).size;

    const OUTPUT_CIPHER_FILE = "./test/random.bin.ciphertext";
    const OUTPUT_PLAIN_FILE = "./test/random.bin.plaintext";

    const cipherStream = cipher.createEncryptionStream({
        key,
        iv: DEMO_IV,
        aad: DEMO_AAD,
        plaintextLength: SOURCE_PLAIN_FILE_SIZE,
        authTagLength: 16
    });

    await _.waitForStream(
        $fs.createReadStream(SOURCE_PLAIN_FILE).pipe(
            cipherStream
        ).pipe(
            $fs.createWriteStream(OUTPUT_CIPHER_FILE)
        )
    );

    const result = cipherStream.getCipherInfo();

    await _.waitForStream(
        $fs.createReadStream(OUTPUT_CIPHER_FILE).pipe(
            cipher.createDecryptionStream({
                key,
                iv: result.iv,
                aad: result.aad,
                plaintextLength: SOURCE_PLAIN_FILE_SIZE,
                authTag: result.authTag
            })
        ).pipe(
            $fs.createWriteStream(OUTPUT_PLAIN_FILE)
        )
    );
})();
