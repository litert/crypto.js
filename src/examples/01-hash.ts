// tslint:disable: no-console

import * as $Crypto from "../lib";
import * as $fs from "fs";

const PLAIN_TEXT = "hello";

/**
 * Do a SHA-512 hash by given hasher.
 */
console.log($Crypto.Hash.SHA512.hash(PLAIN_TEXT).toString("hex"));

/**
 * Enum all hashers.
 */
for (const algo in $Crypto.Hash.hashers) {

    console.log(`${algo.padEnd(16, " ")}: ${$Crypto.Hash.hashers[algo].hash(PLAIN_TEXT).toString("hex")}`);
}

(async () => {

    for (const algo in $Crypto.Hash.hashers) {

        console.log(`[Stream]${algo.padEnd(16, " ")}: ${(
            await $fs.createReadStream("./test/random.bin").pipe(
                $Crypto.Hash.hashers[algo].createStream()
            ).wait()
        ).toString("hex")}`);

        console.log(`[Stream]${algo.padEnd(16, " ")}: ${(
            await $Crypto.Hash.hashers[algo].hashStream($fs.createReadStream("./test/random.bin"))
        ).toString("hex")}`);
    }
})();
