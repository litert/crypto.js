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
