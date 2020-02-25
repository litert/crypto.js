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

export const E_INVALID_KEY_LENGTH = ErrorHub.define(
    null,
    "E_INVALID_KEY_LENGTH",
    "The length of key is not valid for the cipher.",
    {}
);

export const E_INVALID_KEY_FORMAT = ErrorHub.define(
    null,
    "E_INVALID_KEY_FORMAT",
    "The key for cipher must be a string or a buffer.",
    {}
);

export const E_INVALID_IV_FORMAT = ErrorHub.define(
    null,
    "E_INVALID_IV_FORMAT",
    "The IV for cipher must be a buffer.",
    {}
);

export const E_INVALID_IV_LENGTH = ErrorHub.define(
    null,
    "E_INVALID_IV_LENGTH",
    "The length of key is not valid for the cipher.",
    {}
);

export const E_INVALID_STREAM = ErrorHub.define(
    null,
    "E_INVALID_STREAM",
    "A stream is required to be waited for.",
    {}
);

export const E_AAD_REQUIRED = ErrorHub.define(
    null,
    "E_AAD_REQUIRED",
    "For selected cipher mode, additional authenticated data (AAD) is required.",
    {}
);

export const E_INVALID_AAD_FORMAT = ErrorHub.define(
    null,
    "E_INVALID_AAD_FORMAT",
    "The AAD must be a buffer.",
    {}
);

export const E_IV_REQUIRED = ErrorHub.define(
    null,
    "E_IV_REQUIRED",
    "For selected cipher mode, initialization vector (IV) is required.",
    {}
);

export const E_KEY_REQUIRED = ErrorHub.define(
    null,
    "E_KEY_REQUIRED",
    "Key is required for cipher.",
    {}
);

export const E_PLAINTEXT_LENGTH_REQUIRED = ErrorHub.define(
    null,
    "E_PLAINTEXT_LENGTH_REQUIRED",
    "For selected cipher mode, length of plaintext is required.",
    {}
);

export const E_AUTH_TAG_REQUIRED = ErrorHub.define(
    null,
    "E_AUTH_TAG_REQUIRED",
    "For selected cipher mode, authentication tag is required.",
    {}
);

export const E_AUTH_TAG_LENGTH_REQUIRED = ErrorHub.define(
    null,
    "E_AUTH_TAG_LENGTH_REQUIRED",
    "For selected cipher mode, the length of authentication tag is required.",
    {}
);
