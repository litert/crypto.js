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
import * as $Crypto from "crypto";

export default function createHasher(algorithm: string): C.IHasher {

    return (new Function(`createHasher`, `$Crypto`, `return {

        name: "${algorithm}",

        hash(data) {

            return $Crypto.createHash("${algorithm}").update(data).digest();
        },

        hashStream(stream) {

            return stream.pipe(this.createStream()).wait();
        },

        createStream() {

            return Object.defineProperty(
                $Crypto.createHash("${algorithm}"),
                "wait",
                {
                    value() {

                        if (this.writable) {

                            return new Promise((resolve, reject) => {

                                this.on("finish", () => {
                                    resolve(this.digest());
                                }).on("error", (e) => reject(e));
                            });
                        }

                        return Promise.resolve(this.digest());
                    }
                }
            );
        },

        createHasher() {

            return createHasher("${algorithm}");
        }

    };`))(createHasher, $Crypto);
}
