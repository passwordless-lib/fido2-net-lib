"use strict";

const assert = require("chai").assert;
const {
    Msg,
    ServerResponse,
    CreateOptionsRequest,
    CreateOptions,
    CredentialAttestation,
    GetOptionsRequest,
    GetOptions,
    CredentialAssertion,
    WebAuthnOptions
} = require("../../webauthn-simple-app");

describe("WebAuthnApp", function() {
    it("is running on node", function() {
        assert.throws(() => {
            assert.isUndefined(window);
        }, ReferenceError, "window is not defined");
    });

    it("can load", function() {
        assert.isFunction(Msg);
        assert.isFunction(ServerResponse);
        assert.isFunction(CreateOptionsRequest);
        assert.isFunction(CreateOptions);
        assert.isFunction(CredentialAttestation);
        assert.isFunction(GetOptionsRequest);
        assert.isFunction(GetOptions);
        assert.isFunction(CredentialAssertion);
    });

    it("can coerce base64 to Buffer");
    it("can coerce Buffer to base64");
    it("coerceToArrayBuffer doesn't return Buffer");
});
