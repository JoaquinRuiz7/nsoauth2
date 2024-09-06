import {NSOAuth2, Scope} from "./src";

const c = new NSOAuth2({
    clientId: '328045fa92816077b2f0d3dad95f628ea6808298d8d870697981431f6e28a4db',
    clientSecret: '7d98c5a864e079f990515c51ce64ec8eada45da5c02f060acd669d80f20ae248',
    scopes: [Scope.RESTLETS, Scope.REST_WEB_SERVICES],
    redirectUrl: 'http://localhost:3000/test'
});