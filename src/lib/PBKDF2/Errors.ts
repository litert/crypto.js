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

import { ErrorHub } from "../Errors";

export const E_INVALID_KEY_WIDTH = ErrorHub.define(
    null,
    "E_INVALID_KEY_WIDTH",
    "The key-width is invalid.",
    {}
);

export const E_INVALID_ITERATIONS = ErrorHub.define(
    null,
    "E_INVALID_ITERATIONS",
    "The iteration is invalid.",
    {}
);

export const E_NO_KEY_WIDTH = ErrorHub.define(
    null,
    "E_NO_KEY_WIDTH",
    "The key-width is not set.",
    {}
);

export const E_NO_SALT = ErrorHub.define(
    null,
    "E_NO_SALT",
    "The salt is not set.",
    {}
);

export const E_NO_DIGEST_ALGORITHM = ErrorHub.define(
    null,
    "E_NO_DIGEST_ALGORITHM",
    "The digest algorithm is not set.",
    {}
);

export const E_NO_ITERATIONS = ErrorHub.define(
    null,
    "E_NO_ITERATIONS",
    "The iteration is not set.",
    {}
);
