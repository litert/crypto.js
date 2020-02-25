import { Readable, Duplex } from "stream";

export interface IHashStream extends Duplex {

    digest(): Buffer;

    wait(): Promise<Buffer>;
}

export interface IHasher {

    readonly name: string;

    /**
     * Calculate the hash value of the input string or buffer.
     *
     * @param data The string or buffer to be hashed.
     */
    hash(data: Buffer | string): Buffer;

    /**
     * Calculate the hash value of the input stream.
     *
     * @param data The readable stream to be hashed.
     */
    hashStream(stream: Readable): Promise<Buffer>;

    /**
     * Create a Duplex stream to process the hash progress.
     */
    createStream(): IHashStream;

    /**
     * Get a clone of the current hasher.
     */
    createHasher(): IHasher;
}
