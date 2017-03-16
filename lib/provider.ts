import * as childProcess from "child_process";
import { EventEmitter } from "events";

const TOKEN_WATCHER_INTERVAL = 2e3;

type ProviderTokenHandler = (info: { removed: IProvider[], added: IProvider[] }) => void;
type ProviderListeningHandler = (info: IModule) => void;
type ProviderErrorHandler = (e: Error) => void;
type ProviderStopHandler = () => void;

export class Provider extends EventEmitter {

    public readonly library: string;

    protected interval: NodeJS.Timer;

    constructor(lib: string) {
        super();

        this.library = lib;
    }

    public on(event: "stop", listener: ProviderStopHandler): this;
    public on(event: "listening", listener: ProviderListeningHandler): this;
    public on(event: "token", listener: ProviderTokenHandler): this;
    public on(event: "error", listener: ProviderErrorHandler): this;
    // public on(event: string | symbol, listener: Function): this;
    public on(event: string | symbol, listener: Function) {
        return super.on(event, listener);
    }

    public once(event: "stop", listener: ProviderStopHandler): this;
    public once(event: "listening", listener: ProviderListeningHandler): this;
    public once(event: "token", listener: ProviderTokenHandler): this;
    public once(event: "error", listener: ProviderErrorHandler): this;
    // public once(event: string | symbol, listener: Function): this;
    public once(event: string | symbol, listener: Function) {
        return super.once(event, listener);
    }

    public open() {

        this.getInfo((info) => {
            this.emit("listening", info);
            let length = info.providers.length;

            this.interval = setInterval(() => {
                this.getInfo((info2) => {
                    const length2 = info2.providers.length;
                    if (length2 !== length) {
                        const difference = this.findDifference(info.providers, info2.providers);
                        this.emit("token", difference);
                        info = info2;
                        length = length2;
                    }
                });
            }, TOKEN_WATCHER_INTERVAL);
        });

    }

    public stop() {
        clearInterval(this.interval);
    }

    protected findDifference(a: IProvider[], b: IProvider[]) {
        // remove all equal providers from arrays
        a = a.filter((A) => {
            let found = false;
            b = b.filter((B) => {
                if (A.serialNumber === B.serialNumber) {
                    found = true;
                    return false;
                }
                return true;
            });
            return !found;
        });
        return {
            removed: a,
            added: b,
        };
    }

    protected getInfo(cb: (info: IModule) => void) {
        childProcess.exec(`node ${__dirname}/watcher.js ${this.library}`, (error, stdout) => {
            if (error) {
                this.emit("error", error);
            } else {
                if (stdout !== "-1") {
                    cb(JSON.parse(stdout));
                }
            }
        });
    }

}
