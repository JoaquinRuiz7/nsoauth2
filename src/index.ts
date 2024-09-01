import {Oauth2} from "./oauth2";
import {Scope} from "./types/Scope";

const oauth2: Oauth2 = new Oauth2({
    clientId: '7f09f981b861617a1d7cac0199b8112a59c6f5fc6403ae48a37af58bc63119b7',
    clientSecret: 'eee50fa4b3aeb2c62e97513cff19aedcc4455728cc5a321a420260ede03cc5be',
    scopes: [Scope.RESTLETS, Scope.REST_WEB_SERVICES],
    accountId: 5540399
});
oauth2.getAccessToken('Joaco');