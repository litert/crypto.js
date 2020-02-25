import { Readable, Writable } from "stream";

export function waitForStream<T extends Readable | Writable>(stream: T): Promise<T> {

    if (stream instanceof Readable) {

        return new Promise((resolve, reject) => {

            stream.on("end", () => {
                resolve(stream);
            }).on("error", (e) => reject(e));
        });
    }

    return new Promise((resolve, reject) => {

        stream.on("finish", () => {
            resolve(stream);
        }).on("error", (e) => reject(e));
    });
}