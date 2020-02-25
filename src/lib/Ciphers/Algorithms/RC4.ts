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
