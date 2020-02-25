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

import { IHasher } from "../Hash";

export interface IKeyOptions {

    salt: Buffer | string;

    /**
     * The bit-width of key.
     */
    keyWidth: number;

    iterations: number;

    digestHasher: IHasher;
}

export interface IPBKDF2KeyGenerator {

    setSalt(salt: Buffer | string): this;

    getSalt(): Buffer | null;

    setKeyWidth(bits: number): this;

    getKeyWidth(): number | null;

    setIterations(iterations: number): this;

    getIterations(): number | null;

    setDigestHasher(hasher: IHasher): this;

    getDigestHasher(): IHasher | null;

    createSync(
        passphrase: Buffer | string,
        opts?: Partial<IKeyOptions>
    ): Buffer;

    create(
        passphrase: Buffer | string,
        opts?: Partial<IKeyOptions>
    ): Promise<Buffer>;
}
