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
import * as Hash from "../Hash";
import * as E from "./Errors";
import * as $Crypto from "crypto";

type IPrivateData = C.IKeyOptions;

const SECRET_DATA = new WeakMap<C.IPBKDF2KeyGenerator, IPrivateData>();

class PBKDF2KeyGenerator implements C.IPBKDF2KeyGenerator {

    public constructor(defaultOptions: Partial<C.IKeyOptions>) {

        SECRET_DATA.set(this, {} as IPrivateData);

        if (defaultOptions.keyWidth) {

            this.setKeyWidth(defaultOptions.keyWidth);
        }

        if (defaultOptions.salt) {

            this.setSalt(defaultOptions.salt);
        }

        if (defaultOptions.iterations) {

            this.setIterations(defaultOptions.iterations);
        }

        if (defaultOptions.digestHasher) {

            this.setDigestHasher(defaultOptions.digestHasher);
        }
    }

    public setSalt(salt: Buffer | string): this {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        _this.salt = this._processSalt(salt);

        return this;
    }

    public getSalt(): Buffer | null {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        return _this.salt as Buffer || null;
    }

    public setKeyWidth(bits: number): this {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        _this.keyWidth = this._processKeyWidth(bits);

        return this;
    }

    public getKeyWidth(): number | null {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        return _this.keyWidth ? _this.keyWidth : null;
    }

    public setIterations(iterations: number): this {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        _this.iterations = this._processIteration(iterations);

        return this;
    }

    public getIterations(): number | null {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        return _this.iterations || null;
    }

    public setDigestHasher(algo: Hash.IHasher): this {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        _this.digestHasher = this._processDigestAlgo(algo);

        return this;
    }

    public getDigestHasher(): Hash.IHasher | null {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        return _this.digestHasher || null;
    }

    private _processIteration(v?: number): number {

        if (v === undefined) {

            throw new E.E_NO_ITERATIONS();
        }

        if (!Number.isSafeInteger(v) || v < 1) {

            throw new E.E_INVALID_ITERATIONS();
        }

        return v;
    }

    private _processKeyWidth(v?: number): number {

        if (v === undefined) {

            throw new E.E_NO_KEY_WIDTH();
        }

        if (!Number.isSafeInteger(v) || v < 8 || v % 8) {

            throw new E.E_INVALID_KEY_WIDTH();
        }

        return v;
    }

    private _processDigestAlgo(v?: Hash.IHasher): Hash.IHasher {

        if (v === undefined) {

            throw new E.E_NO_DIGEST_ALGORITHM();
        }

        return v;
    }

    private _processSalt(v?: Buffer | string): Buffer {

        if (v === undefined) {

            throw new E.E_NO_SALT();
        }

        if (typeof v === "string") {

            return Buffer.from(v);
        }

        return v;
    }
    public createSync(
        passphrase: Buffer | string,
        opts?: Partial<C.IKeyOptions>
    ): Buffer {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        const digestAlgo = this._processDigestAlgo(opts?.digestHasher || _this.digestHasher);

        const salt = this._processSalt(opts?.salt || _this.salt);

        const iterations = this._processIteration(opts?.iterations || _this.iterations);

        const keyWidth = this._processKeyWidth(opts?.keyWidth ? opts?.keyWidth : _this.keyWidth) / 8;

        return $Crypto.pbkdf2Sync(
            passphrase,
            salt,
            iterations,
            keyWidth,
            digestAlgo.name
        );
    }

    public create(
        passphrase: Buffer | string,
        opts?: Partial<C.IKeyOptions>
    ): Promise<Buffer> {

        const _this = SECRET_DATA.get(this) as IPrivateData;

        const digestAlgo = this._processDigestAlgo(opts?.digestHasher || _this.digestHasher);

        const salt = this._processSalt(opts?.salt || _this.salt);

        const iterations = this._processIteration(opts?.iterations || _this.iterations);

        const keyWidth = this._processKeyWidth(opts?.keyWidth ? opts?.keyWidth : _this.keyWidth) / 8;

        return new Promise((resolve, reject) => {
            $Crypto.pbkdf2(
                passphrase,
                salt,
                iterations,
                keyWidth,
                digestAlgo.name,
                function(e, k) {

                    if (e) {

                        return reject(e);
                    }

                    resolve(k);
                }
            );
        });
    }
}

export function createPBKDF2KeyGenerator(
    opts: Partial<C.IKeyOptions> = {}
): C.IPBKDF2KeyGenerator {

    return new PBKDF2KeyGenerator(opts);
}
