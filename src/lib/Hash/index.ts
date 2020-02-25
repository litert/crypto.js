export * from "./Common";
import createHasher from "./Hashers";
import { IHasher } from "./Common";
import * as $Crypto from "crypto";

export const hashers: Record<string, IHasher> = {};

for (const algo of $Crypto.getHashes()) {

    if (algo.toLowerCase().includes("rsa")) {

        continue;
    }

    hashers[algo] = exports[algo.toUpperCase().replace("-", "_")] = createHasher(algo);
}

export declare const BLAKE2B512: IHasher;

export declare const BLAKE2S256: IHasher;

export declare const MD4: IHasher;

export declare const MD5: IHasher;

export declare const MD5_SHA1: IHasher;

export declare const MDC2: IHasher;

export declare const RIPEMD: IHasher;

export declare const RIPEMD160: IHasher;

export declare const RMD160: IHasher;

export declare const SHA1: IHasher;

export declare const SHA224: IHasher;

export declare const SHA256: IHasher;

export declare const SHA3_224: IHasher;

export declare const SHA3_256: IHasher;

export declare const SHA3_384: IHasher;

export declare const SHA3_512: IHasher;

export declare const SHA384: IHasher;

export declare const SHA512: IHasher;

export declare const SHA512_224: IHasher;

export declare const SHA512_256: IHasher;

export declare const SHAKE128: IHasher;

export declare const SHAKE256: IHasher;

export declare const SM3: IHasher;

export declare const SSL3_MD5: IHasher;

export declare const SSL3_SHA1: IHasher;

export declare const WHIRLPOOL: IHasher;

