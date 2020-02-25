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

import { Readable, Duplex } from "stream";

export interface IHashStream extends Duplex {

    digest(): Buffer;

    wait(): Promise<Buffer>;
}

export interface IHasher {

    readonly name: string;

    /**
     * Calculate the hash value of the input string or buffer.
     *
     * @param data The string or buffer to be hashed.
     */
    hash(data: Buffer | string): Buffer;

    /**
     * Calculate the hash value of the input stream.
     *
     * @param data The readable stream to be hashed.
     */
    hashStream(stream: Readable): Promise<Buffer>;

    /**
     * Create a Duplex stream to process the hash progress.
     */
    createStream(): IHashStream;

    /**
     * Get a clone of the current hasher.
     */
    createHasher(): IHasher;
}
