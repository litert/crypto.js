// tslint:disable: no-console

import * as $Crypto from "../lib";
import * as $fs from "fs";
import * as _ from "./Utils";

const PBKDF2_SALT = "@litert/crypto";
const PBKDF2_ITERATION = 100;

const DEMO_PASSPHRASE = "I am rock!";
const DEMO_PLAINTEXT = "hello world!";

const key = $Crypto.PBKDF2.createPBKDF2KeyGenerator({
    digestHasher: $Crypto.Hash.SHA256,
    salt: PBKDF2_SALT,
    iterations: PBKDF2_ITERATION,
}).createSync(DEMO_PASSPHRASE, {
    keyWidth: 128
});

const cipher = $Crypto.Ciphers.AES.ECB;

const result = cipher.encrypt(DEMO_PLAINTEXT, { key, autoPadding: true });

console.log(result.ciphertext.toString("hex"));

console.log(cipher.decrypt(result.ciphertext, { key, autoPadding: true }).toString());

(async () => {

    await _.waitForStream(
        $fs.createReadStream("./test/random.bin").pipe(
            cipher.createEncryptionStream({key})
        ).pipe(
            $fs.createWriteStream("./test/random.bin.ciphertext")
        )
    );

    await _.waitForStream(
        $fs.createReadStream("./test/random.bin.ciphertext").pipe(
            cipher.createDecryptionStream({key})
        ).pipe(
            $fs.createWriteStream("./test/random.bin.plaintext")
        )
    );
})();
