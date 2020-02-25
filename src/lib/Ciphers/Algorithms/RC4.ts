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
import createCipher from "../Cipher";

/**
 * - RC4: at least 8-bit key is required.
 *
 * No requirement for `iv`, `authTag`, `aad` and `plaintextLength`.
 *
 * @deprecated RC4 is not safe anymore, don't use it for any security purpose.
 */
export const RC4 = createCipher(
    "rc4",
    "",
    function(key: Buffer): any {

        if (!(key instanceof Buffer)) {

            return new E.E_INVALID_KEY_FORMAT();
        }

        if (key.byteLength < 1) {

            return new E.E_INVALID_KEY_LENGTH();
        }

    },
    () => `"rc4"`
);
