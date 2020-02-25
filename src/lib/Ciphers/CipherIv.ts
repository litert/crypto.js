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

export default function createCipherIv(
    algo: string,
    mode: string,
    validateKey: (key: Buffer) => any,
    validateIv: (key: Buffer, iv: Buffer) => any,
    generateIv: (key: Buffer) => Buffer,
    generateCipherName: (keyVar: string, mode: string) => string
): C.ICipher {

    return (new Function(
        `createCipherIv`,
        `Errors`,
        `$Crypto`,
        `_validateKey`,
        `_validateIv`,
        `_generateIv`,
        `_generateCipherName`,
        // begin
        `
        function _check_key(key) {

            const result = _validateKey(key);

            if (result) {

                throw result;
            }
        }

        function _check_iv(key, iv) {

            const result = _validateIv(key, iv);

            if (result) {

                throw result;
            }

            return iv;
        }

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

                    _check_key(opts.key);

                    const iv = _check_iv(opts.key, opts.iv || _generateIv(opts.key));

                    const cipherName = ${ generateCipherName("opts.key", mode) };

                    const cipher = $Crypto.createCipheriv(
                        cipherName,
                        opts.key,
                        iv
                    );

                    if (opts.autoPadding) {

                        cipher.setAutoPadding(true);
                    }

                    return {
                        ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]),
                        iv,
                        autoPadding: opts.autoPadding,
                        cipher: cipherName
                    };
                }
            },

            decrypt: {
                "writable": false,
                "configurable": false,
                value(ciphertext, opts) {

                    _check_key(opts.key);

                    _check_iv(opts.key, opts.iv);

                    const decipher = $Crypto.createDecipheriv(
                        ${ generateCipherName("opts.key", mode) },
                        opts.key,
                        opts.iv
                    );

                    if (opts.autoPadding) {

                        decipher.setAutoPadding(true);
                    }

                    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
                }
            },

            createEncryptionStream: {
                "writable": false,
                "configurable": false,
                value(opts) {

                    _check_key(opts.key);

                    const iv = _check_iv(opts.key, opts.iv || _generateIv(opts.key));

                    const cipherName = ${ generateCipherName("opts.key", mode) };

                    const cipher = $Crypto.createCipheriv(
                        cipherName,
                        opts.key,
                        iv
                    );

                    if (opts.autoPadding) {

                        cipher.setAutoPadding(true);
                    }

                    return Object.defineProperty(
                        cipher,
                        "getCipherInfo",
                        {
                            value() {

                                return {
                                    iv,
                                    autoPadding: opts.autoPadding,
                                    cipher: cipherName
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

                    _check_key(opts.key);

                    _check_iv(opts.key, opts.iv);

                    const decipher = $Crypto.createDecipheriv(
                        ${ generateCipherName("opts.key", mode) },
                        opts.key,
                        opts.iv
                    );

                    if (opts.autoPadding) {

                        decipher.setAutoPadding(true);
                    }

                    return decipher;
                }
            },

            createCipher: {
                "writable": false,
                "configurable": false,
                value() {

                    return createCipherIv(
                        "${algo}",
                        "${mode}",
                        _validateKey,
                        _validateIv,
                        _generateIv,
                        _generateCipherName,
                    );
                }
            }

    });`))(
        createCipherIv,
        E,
        $Crypto,
        validateKey,
        validateIv,
        generateIv,
        generateCipherName
    );
}
