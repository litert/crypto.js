/**
 * Copyright 2020 Angus.Fenying <fenying@litert.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import * as C from "./Common";
import * as E from "./Errors";
import * as $Crypto from "crypto";

export default function createCipherAuth(
    algo: string,
    mode: string,
    validateKey: (key: Buffer) => any,
    validateIv: (key: Buffer, iv: Buffer) => any,
    validateOptions: (opts: C.IDecipherOptions, decryption?: boolean) => C.IDecipherOptions,
    generateIv: (key: Buffer) => Buffer,
    generateCipherName: (keyVar: string, mode: string) => string,
): C.ICipher {

    return (new Function(
        `createCipherAuth`,
        `Errors`,
        `$Crypto`,
        `_validateKey`,
        `_validateIv`,
        `_validateOptions`,
        `_generateIv`,
        // begin
        `
        return Object.defineProperties({}, {

            "algorithm": {
                "value": "${algo}",
                "writable": false,
                "configurable": false
            },

            "mode": {
                "value": "${mode}",
                "writable": false,
                "configurable": false
            },

            validateKey: {
                value(key) {

                    if (!(key instanceof Buffer)) {

                        return false;
                    }

                    return !_validateKey(key);
                },
                "writable": false,
                "configurable": false
            },

            validateIv: {
                "writable": false,
                "configurable": false,
                value(key, iv) {

                    if (!(iv instanceof Buffer)) {

                        return false;
                    }

                    return !_validateIv(key, iv);
                }
            },

            generateIv: {
                "writable": false,
                "configurable": false,
                value(key) {

                    return _generateIv(key);
                }
            },

            encrypt: {
                "writable": false,
                "configurable": false,
                value(plaintext, opts) {

                    if (!opts.iv) {
                        opts.iv = _generateIv(opts.key);
                    }

                    opts = _validateOptions(opts);

                    const cipherOptions = {};

                    if (opts.authTagLength) {

                        cipherOptions.authTagLength = opts.authTagLength;
                    }

                    const cipherName = ${ generateCipherName("opts.key", mode) };

                    const cipher = $Crypto.createCipheriv(
                        cipherName,
                        opts.key,
                        opts.iv,
                        cipherOptions
                    );

                    if (opts.autoPadding) {

                        cipher.setAutoPadding(true);
                    }

                    if (opts.aad) {

                        cipher.setAAD(
                            opts.aad,
                            opts.plaintextLength ?
                                { plaintextLength: opts.plaintextLength } :
                                undefined
                        );
                    }

                    return {
                        ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]),
                        iv: opts.iv,
                        autoPadding: opts.autoPadding,
                        cipher: cipherName,
                        authTag: cipher.getAuthTag(),
                        aad: opts.aad,
                        plaintextLength: opts.plaintextLength
                    };
                }
            },

            decrypt: {
                "writable": false,
                "configurable": false,
                value(ciphertext, opts) {

                    opts = _validateOptions(opts, true);

                    const cipherOptions = {};

                    if (opts.authTagLength) {

                        cipherOptions.authTagLength = opts.authTagLength;
                    }

                    const decipher = $Crypto.createDecipheriv(
                        ${ generateCipherName("opts.key", mode) },
                        opts.key,
                        opts.iv,
                        cipherOptions
                    );

                    if (opts.autoPadding) {

                        decipher.setAutoPadding(true);
                    }

                    if (opts.aad) {

                        decipher.setAAD(
                            opts.aad,
                            opts.plaintextLength ?
                                { plaintextLength: opts.plaintextLength } :
                                undefined
                        );
                    }

                    if (opts.authTag) {

                        decipher.setAuthTag(opts.authTag);
                    }

                    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
                }
            },

            createEncryptionStream: {
                "writable": false,
                "configurable": false,
                value(opts) {

                    if (!opts.iv) {
                        opts.iv = _generateIv(opts.key);
                    }

                    opts = _validateOptions(opts);

                    const cipherOptions = {};

                    if (opts.authTagLength) {

                        cipherOptions.authTagLength = opts.authTagLength;
                    }

                    const cipherName = ${ generateCipherName("opts.key", mode) };

                    const cipher = $Crypto.createCipheriv(
                        cipherName,
                        opts.key,
                        opts.iv,
                        cipherOptions
                    );

                    if (opts.autoPadding) {

                        cipher.setAutoPadding(true);
                    }

                    if (opts.aad) {

                        cipher.setAAD(
                            opts.aad,
                            opts.plaintextLength ?
                                { plaintextLength: opts.plaintextLength } :
                                undefined
                        );
                    }

                    return Object.defineProperty(
                        cipher,
                        "getCipherInfo",
                        {
                            "writable": false,
                            "configurable": false,
                            value() {

                                return {
                                    iv: opts.iv,
                                    autoPadding: opts.autoPadding,
                                    cipher: cipherName,
                                    authTag: cipher.getAuthTag(),
                                    aad: opts.aad,
                                    plaintextLength: opts.plaintextLength
                                };
                            }
                        }
                    );
                }
            },

            createDecryptionStream: {
                "writable": false,
                "configurable": false,
                value(opts) {

                    opts = _validateOptions(opts, true);

                    const cipherOptions = {};

                    if (opts.authTagLength) {

                        cipherOptions.authTagLength = opts.authTagLength;
                    }

                    const decipher = $Crypto.createDecipheriv(
                        ${ generateCipherName("opts.key", mode) },
                        opts.key,
                        opts.iv,
                        cipherOptions
                    );

                    if (opts.autoPadding) {

                        decipher.setAutoPadding(true);
                    }

                    if (opts.aad) {

                        decipher.setAAD(
                            opts.aad,
                            opts.plaintextLength ?
                                { plaintextLength: opts.plaintextLength } :
                                undefined
                        );
                    }

                    if (opts.authTag) {

                        decipher.setAuthTag(opts.authTag);
                    }

                    return decipher;
                }
            },

            createCipher: {
                "writable": false,
                "configurable": false,
                value() {

                    return createCipherAuth(
                        "${algo}",
                        "${mode}",
                        _validateKey,
                        _validateIv,
                        _validateOptions,
                        _generateIv,
                    );
                }
            }

    });`))(
        createCipherAuth,
        E,
        $Crypto,
        validateKey,
        validateIv,
        validateOptions,
        generateIv
    );
}
