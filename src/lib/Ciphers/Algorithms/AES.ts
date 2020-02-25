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

import * as E from "../Errors";
import createCipherIv from "../CipherIv";
import createCipher from "../Cipher";
import createCipherAuth from "../CipherAuth";
import * as $Crypto from "crypto";

function GENERAL_AES_KEY_VALIDATOR(key: Buffer): any {

    if (!(key instanceof Buffer)) {

        return new E.E_INVALID_KEY_FORMAT();
    }

    if (key.byteLength !== 16 && key.byteLength !== 32 && key.byteLength !== 24) {

        return new E.E_INVALID_KEY_LENGTH();
    }
}

function GENERAL_AES_IV_VALIDATOR(key: Buffer, iv: Buffer): any {

    if (!(iv instanceof Buffer)) {

        return new E.E_INVALID_IV_FORMAT();
    }

    if (iv.byteLength !== 16) {

        return new E.E_INVALID_IV_LENGTH();
    }
}

function GENERAL_AES_IV_GENERATOR(key: Buffer): Buffer {

    return $Crypto.randomBytes(16);
}

function GENERAL_AES_CIPHER_GENERATOR(keyVar: string, mode: string): string {

    return `\`aes-\${${keyVar}.byteLength * 8}-${mode}\``;
}

/**
 * - AES-128-ECB: 128-bit key is required.
 * - AES-192-ECB: 192-bit key is required.
 * - AES-256-ECB: 256-bit key is required.
 *
 * No requirement for `iv`, `authTag`, `aad` and `plaintextLength`.
 *
 * @deprecated ECB mode doesn't work with IV, so that it could be detected by plaintext pattern.
 */
export const ECB = createCipher(
    "aes",
    "ecb",
    GENERAL_AES_KEY_VALIDATOR,
    GENERAL_AES_CIPHER_GENERATOR
);

/**
 * - AES-128-CFB: 128-bit key and 128-bit IV are required.
 * - AES-192-CFB: 192-bit key and 128-bit IV are required.
 * - AES-256-CFB: 256-bit key and 128-bit IV are required.
 *
 * No requirement for `authTag`, `aad` and `plaintextLength`.
 */
export const CFB = createCipherIv(
    "aes",
    "cfb",
    GENERAL_AES_KEY_VALIDATOR,
    GENERAL_AES_IV_VALIDATOR,
    GENERAL_AES_IV_GENERATOR,
    GENERAL_AES_CIPHER_GENERATOR
);

/**
 * - AES-128-OFB: 128-bit key and 128-bit IV are required.
 * - AES-192-OFB: 192-bit key and 128-bit IV are required.
 * - AES-256-OFB: 256-bit key and 128-bit IV are required.
 *
 * No requirement for `authTag`, `aad` and `plaintextLength`.
 */
export const OFB = createCipherIv(
    "aes",
    "ofb",
    GENERAL_AES_KEY_VALIDATOR,
    GENERAL_AES_IV_VALIDATOR,
    GENERAL_AES_IV_GENERATOR,
    GENERAL_AES_CIPHER_GENERATOR
);

/**
 * - AES-128-CBC: 128-bit key and 128-bit IV are required.
 * - AES-192-CBC: 192-bit key and 128-bit IV are required.
 * - AES-256-CBC: 256-bit key and 128-bit IV are required.
 *
 * No requirement for `authTag`, `aad` and `plaintextLength`.
 */
export const CBC = createCipherIv(
    "aes",
    "cbc",
    GENERAL_AES_KEY_VALIDATOR,
    GENERAL_AES_IV_VALIDATOR,
    GENERAL_AES_IV_GENERATOR,
    GENERAL_AES_CIPHER_GENERATOR
);

/**
 * - AES-128-CTR: 128-bit key and 128-bit IV are required.
 * - AES-192-CTR: 192-bit key and 128-bit IV are required.
 * - AES-256-CTR: 256-bit key and 128-bit IV are required.
 *
 * No requirement for `authTag`, `aad` and `plaintextLength`.
 */
export const CTR = createCipherIv(
    "aes",
    "ctr",
    GENERAL_AES_KEY_VALIDATOR,
    GENERAL_AES_IV_VALIDATOR,
    GENERAL_AES_IV_GENERATOR,
    GENERAL_AES_CIPHER_GENERATOR
);

/**
 * For XTS mode, the minimum length of plaintext is 16 bytes.
 *
 * - AES-128-XTS: 256-bit key and 128-bit IV are required.
 * - AES-256-XTS: 512-bit key and 128-bit IV are required.
 *
 * No requirement for `authTag`, `aad` and `plaintextLength`.
 */
export const XTS = createCipherIv(
    "aes",
    "xts",
    function(key): any {

        if (key.byteLength !== 32 && key.byteLength !== 64) {

            return new E.E_INVALID_KEY_LENGTH();
        }
    },
    GENERAL_AES_IV_VALIDATOR,
    GENERAL_AES_IV_GENERATOR,
    function(keyVar, mode): string {
        return `\`aes-\${${keyVar}.byteLength * 4}-${mode}\``;
    },
);

function CCM_IV_VALIDATOR(key: Buffer, iv: Buffer): any {

    if (!(iv instanceof Buffer)) {

        return new E.E_INVALID_IV_FORMAT();
    }

    if (iv.byteLength > 13 || iv.byteLength < 7) {

        return new E.E_INVALID_IV_LENGTH();
    }
}

function CCM_IV_GENERATOR(key: Buffer): Buffer {

    /**
     * 7 ~ 13 bytes.
     */
    return $Crypto.randomBytes(Math.floor(Math.random() * 7) + 7);
}

/**
 * - AES-128-CCM: 128-bit key and 56-bit ~ 104-bit IV are required.
 * - AES-192-CCM: 192-bit key and 56-bit ~ 104-bit IV are required.
 * - AES-256-CCM: 256-bit key and 56-bit ~ 104-bit IV are required.
 *
 * `aad` and `plaintextLength`, `authTagLength` are required. Besides, `authTag`
 * is required for decryption.
 *
 * The value of authTagLength could be 4, 6, 8, 12, 14, 16.
 */
export const CCM = createCipherAuth(
    "aes",
    "ccm",
    GENERAL_AES_KEY_VALIDATOR,
    CCM_IV_VALIDATOR,
    function(opts, decryption) {

        let err = GENERAL_AES_KEY_VALIDATOR(opts.key);

        if (err) {

            throw err;
        }

        if (err = CCM_IV_VALIDATOR(opts.key, opts.iv as Buffer)) {

            throw err;
        }

        if (!(opts.aad instanceof Buffer)) {

            throw new E.E_AAD_REQUIRED();
        }

        if (!Number.isInteger(opts.authTagLength as number)) {

            if (opts.authTag instanceof Buffer) {

                opts.authTagLength = opts.authTag.byteLength;
            }
            else {

                throw new E.E_AUTH_TAG_LENGTH_REQUIRED();
            }
        }

        if (!Number.isInteger(opts.plaintextLength as number)) {

            throw new E.E_PLAINTEXT_LENGTH_REQUIRED();
        }

        if (decryption && !(opts.authTag instanceof Buffer)) {

            throw new E.E_AUTH_TAG_REQUIRED();
        }

        return opts;
    },
    CCM_IV_GENERATOR,
    GENERAL_AES_CIPHER_GENERATOR
);

function GCM_IV_VALIDATOR(key: Buffer, iv: Buffer): any {

    if (!(iv instanceof Buffer)) {

        return new E.E_INVALID_IV_FORMAT();
    }

    if (iv.byteLength < 1) {

        return new E.E_INVALID_IV_LENGTH();
    }
}

function GCM_IV_GENERATOR(key: Buffer): Buffer {

    return $Crypto.randomBytes(12);
}

/**
 * - AES-128-GCM: 128-bit key and at least 8-bit IV are required.
 * - AES-192-GCM: 192-bit key and at least 8-bit IV are required.
 * - AES-256-GCM: 256-bit key and at least 8-bit IV are required.
 *
 * Note: For GCM mode, 96-bit IV is recommended.
 *
 * @see https://crypto.stackexchange.com/a/41610
 *
 * `aad` and `plaintextLength`, `authTagLength` are optional. Besides, `authTag`
 * is required for decryption.
 */
export const GCM = createCipherAuth(
    "aes",
    "gcm",
    GENERAL_AES_KEY_VALIDATOR,
    GCM_IV_VALIDATOR,
    function(opts, decryption) {

        let err = GENERAL_AES_KEY_VALIDATOR(opts.key);

        if (err) {

            throw err;
        }

        if (err = GCM_IV_VALIDATOR(opts.key, opts.iv as Buffer)) {

            throw err;
        }

        if (opts.aad !== undefined && !(opts.aad instanceof Buffer)) {

            throw new E.E_INVALID_AAD_FORMAT();
        }

        if (opts.authTagLength !== undefined && !Number.isInteger(opts.authTagLength as number)) {

            if (opts.authTag instanceof Buffer) {

                opts.authTagLength = opts.authTag.byteLength;
            }
            else {

                throw new E.E_AUTH_TAG_LENGTH_REQUIRED();
            }
        }

        if (opts.plaintextLength !== undefined && !Number.isInteger(opts.plaintextLength as number)) {

            throw new E.E_PLAINTEXT_LENGTH_REQUIRED();
        }

        if (decryption && !(opts.authTag instanceof Buffer)) {

            throw new E.E_AUTH_TAG_REQUIRED();
        }

        return opts;
    },
    GCM_IV_GENERATOR,
    GENERAL_AES_CIPHER_GENERATOR
);
