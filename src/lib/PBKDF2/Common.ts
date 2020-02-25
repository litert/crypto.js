import { IHasher } from "../Hash";

export interface IKeyOptions {

    salt: Buffer | string;

    /**
     * The bit-width of key.
     */
    keyWidth: number;

    iterations: number;

    digestHasher: IHasher;
}

export interface IPBKDF2KeyGenerator {

    setSalt(salt: Buffer | string): this;

    getSalt(): Buffer | null;

    setKeyWidth(bits: number): this;

    getKeyWidth(): number | null;

    setIterations(iterations: number): this;

    getIterations(): number | null;

    setDigestHasher(hasher: IHasher): this;

    getDigestHasher(): IHasher | null;

    createSync(
        passphrase: Buffer | string,
        opts?: Partial<IKeyOptions>
    ): Buffer;

    create(
        passphrase: Buffer | string,
        opts?: Partial<IKeyOptions>
    ): Promise<Buffer>;
}
