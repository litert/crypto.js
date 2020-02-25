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
