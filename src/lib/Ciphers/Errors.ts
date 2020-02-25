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
