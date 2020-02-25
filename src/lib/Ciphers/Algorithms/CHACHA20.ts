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

import * as $Crypto from "crypto";
import * as E from "../Errors";
import createCipherIv from "../CipherIv";
import createCipherAuth from "../CipherAuth";

/**
 * - CHACHA20: 256-bit key and 128-bit IV are required.
 *
 * No requirement for `authTag`, `aad` and `plaintextLength`.
 */
export const CHACHA20 = createCipherIv(
    "chacha20",
    "",
    function(key: Buffer): any {

        if (!(key instanceof Buffer)) {

            return new E.E_INVALID_KEY_FORMAT();
        }

        if (key.byteLength !== 32) {

            return new E.E_INVALID_KEY_LENGTH();
        }
    },
    function(key: Buffer, iv: Buffer): any {

        if (!(iv instanceof Buffer)) {

            return new E.E_INVALID_IV_FORMAT();
        }

        if (iv.byteLength !== 16) {

            return new E.E_INVALID_IV_LENGTH();
        }
    },
    () => $Crypto.randomBytes(16),
    () => `"chacha20"`
);

/**
 * - CHACHA20-POLY1305: 256-bit key and 96-bit IV are required.
 *
 * @see https://stackoverflow.com/q/56250245
 *
 * `aad` is optional. Besides, `authTag` is required for decryption.
 */
export const CHACHA20_POLY1305 = createCipherAuth(
    "chacha20",
    "poly1305",
    function(key: Buffer): any {

        if (!(key instanceof Buffer)) {

            return new E.E_INVALID_KEY_FORMAT();
        }

        if (key.byteLength !== 32) {

            return new E.E_INVALID_KEY_LENGTH();
        }
    },
    function(key: Buffer, iv: Buffer): any {

        if (!(iv instanceof Buffer)) {

            return new E.E_INVALID_IV_FORMAT();
        }

        if (iv.byteLength !== 12) {

            return new E.E_INVALID_IV_LENGTH();
        }
    },
    function(opts, decryption) {

        if (!(opts.key instanceof Buffer)) {

            throw new E.E_INVALID_KEY_FORMAT();
        }

        if (opts.key.byteLength !== 32) {

            throw new E.E_INVALID_KEY_LENGTH();
        }

        if (opts.iv !== undefined) {

            if (!(opts.iv instanceof Buffer)) {

                throw new E.E_INVALID_IV_FORMAT();
            }

            if (opts.iv.byteLength !== 12) {

                throw new E.E_INVALID_IV_LENGTH();
            }
        }

        if (opts.aad !== undefined && !(opts.aad instanceof Buffer)) {

            throw new E.E_INVALID_AAD_FORMAT();
        }

        if (decryption && !(opts.authTag instanceof Buffer)) {

            throw new E.E_AUTH_TAG_REQUIRED();
        }

        opts.authTagLength = 16;

        return opts;
    },
    () => $Crypto.randomBytes(12),
    () => `"chacha20-poly1305"`
);
