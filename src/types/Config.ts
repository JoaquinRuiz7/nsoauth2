import {Scope} from "./Scope";

export interface Config {
    clientId: string;
    scopes: Scope[];
    clientSecret: string;
    accountId?: string;
    redirectUrl: string;
}