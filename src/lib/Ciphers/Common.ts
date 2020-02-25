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

import { Duplex } from "stream";

export interface ICipherOptions {

    /**
     * The key for encryption/decryption.
     */
    "key": Buffer;

    /**
     * The initialization vector.
     *
     * If IV is not passed but needed, a random IV will be used.
     *
     * NOTES: Ignored by ECB mode.
     */
    "iv"?: Buffer;

    /**
     * Append 0x00 bytes to the ending in need.
     *
     * @default false
     */
    "autoPadding"?: boolean;

    /**
     * The length (in bytes) of plaintext.
     *
     * NOTES: Required by CCM mode.
     */
    "plaintextLength"?: number;

    /**
     * The additional authenticated data for OCB/GCM/CCM mode.
     */
    "aad"?: Buffer;

    /**
     * The length (in bytes) of authentication tag for GCM/CCM/OCB mode.
     *
     * This field could be omitted if `authTag` is specific while decryption.
     */
    "authTagLength"?: number;
}

export interface IDecipherOptions extends ICipherOptions {

    /**
     * The authentication tag for GCM/CCM/OCB mode.
     */
    "authTag"?: Buffer;
}

export interface IEncryptionResult {

    "ciphertext": Buffer;

    "cipher": string;
}

export interface IEncryptionExtraResult {

    /**
     * The IV used in encryption.
     *
     * NOTES: Ignored by ECB mode.
     */
    "iv"?: Buffer;

    /**
     * The authentication tag for GCM/CCM/OCB mode.
     */
    "authTag"?: Buffer;

    /**
     * Auto pad 0x00 bytes to the ending.
     */
    "autoPadding"?: boolean;

    /**
     * The length (in bytes) of plaintext, used in CCM mode.
     */
    "plaintextLength"?: number;

    /**
     * The additional authenticated data for OCB/GCM/CCM mode.
     */
    "aad"?: Buffer;
}

export interface ICipherStream<R> extends Duplex {

    getCipherInfo(): R;
}

export interface ICipher {

    readonly algorithm: string;

    readonly mode: string;

    validateKey(key: Buffer): boolean;

    validateIv(key: Buffer, iv: Buffer): boolean;

    generateIv(key: Buffer): Buffer;

    /**
     * Get a clone of the current cipher
     */
    createCipher(): ICipher;

    encrypt(
        plaintext: string | Buffer,
        opts: ICipherOptions
    ): IEncryptionResult & IEncryptionExtraResult;

    decrypt(
        ciphertext: Buffer,
        opts: IDecipherOptions
    ): Buffer;

    createEncryptionStream(opts: ICipherOptions): ICipherStream<IEncryptionExtraResult>;

    createDecryptionStream(opts: IDecipherOptions): Duplex;
}
