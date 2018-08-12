/* globals chai, sinon, fido2Helpers
   WebAuthnHelpers, Msg, ServerResponse,
   CreateOptionsRequest, CreateOptions,
   CredentialAttestation,
   GetOptionsRequest, GetOptions,
   CredentialAssertion,
   WebAuthnOptions
 */

"use strict";

var assert = chai.assert;
mocha.setup("bdd");

function serverMock() {
    var server;
    beforeEach(() => {
        server = sinon.fakeServer.create();
        server.respondImmediately = true;
    });
    afterEach(() => {
        server.restore();
    });
    function serverFake(url, data) {
        server.respondWith("POST", url, [200, {
            "Content-Type": "application/json"
        }, JSON.stringify([data])]);
    }

    return serverFake;
}

var cleanUpListeners = [];
function removeAllListeners() {
    for (let listener of cleanUpListeners) {
        document.removeEventListener(listener.type, listener.catchEventFn);
    }
    cleanUpListeners = [];
}

function catchEvent(type, cb) {
    if (typeof cb !== "function") {
        throw new Error("test error: didn't specify callback");
    }

    return new Promise(function (resolve) {
        document.addEventListener(type, catchEventFn);
        cleanUpListeners.push({ type,
            catchEventFn });
        function catchEventFn(event) {
            if (event.type === type) {
                if (cb(event)) { // eslint-disable-line callback-return
                    // console.log("catchEvent done");
                    resolve();
                }
            }
        }
    });
}

/**** TESTING POLYFILL *******/
var sc = Object.getOwnPropertyDescriptor(window, "isSecureContext");
if (sc) {
    if (sc.set || sc.writable) window.isSecureContext = true;
}

try {
    window.isSecureContext = true;
} catch (err) {
    // ignore error
}

if (!window.PublicKeyCredential) {
    window.PublicKeyCredential = function PublicKeyCredential() {}; // eslint-disable-line func-names
    window.PublicKeyCredential.prototype = {};
}

if (!window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = function isUserVerifyingPlatformAuthenticatorAvailable() {}; // eslint-disable-line func-names
}

if (!navigator.credentials) {
    navigator.credentials = {};
}

if (!navigator.credentials.create) {
    navigator.credentials.create = function create() {}; // eslint-disable-line func-names
}

if (!navigator.credentials.get) {
    navigator.credentials.get = function get() {}; // eslint-disable-line func-names
}
/**** END TESTING POLYFILL *******/

describe.skip("debug", () => {
    it("isSecureContext", () => {
        assert.isTrue(window.isSecureContext);
    });

    it("has PublicKeyCredential", () => {
        assert.isFunction(window.PublicKeyCredential);
    });

    it("has PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable", () => {
        assert.isFunction(window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable);
    });

    it("instanceof", () => {
        var testCred = fido2Helpers.functions.cloneObject(fido2Helpers.lib.makeCredentialAttestationU2fResponse);
        Object.setPrototypeOf(testCred, window.PublicKeyCredential.prototype);
        assert.isTrue(testCred instanceof window.PublicKeyCredential);
    });
});

describe("WebAuthnApp", () => {
    afterEach(() => {
        removeAllListeners();
    });

    var app;
    beforeEach(() => {
        app = new window.WebAuthnApp();
    });

    it("exists", () => {
        assert.isFunction(window.WebAuthnApp);
    });

    it("is constructor", () => {
        assert.isObject(app);
    });

    describe("loading", () => {
        it("is null in insecure context");
        it("is null where WebAuthn API doesn't exist");
    });

    describe("events", () => {
        it("debug on send");
        it("debug on receive");
        it("on load");
    });

    describe("config", () => {
        it("can change endpoints");
        it("can change methods");
        it("can set send callback");
        it("can set receive callback");
    });

    describe("send", () => {
        var serverFake = serverMock();
        class TestMsg extends ServerResponse {
            constructor() {
                super();

                this.propList = this.propList.concat([
                    "id",
                    "comment"
                ]);
            }

            validate() {}
        }

        it("returns promise", () => {
            serverFake("/foo", {
                status: "ok",
                id: 42,
                comment: "hello from outer space"
            });
            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });
            var p = app.send("POST", "/foo", msg, TestMsg);
            assert.instanceOf(p, Promise);
        });

        it("delivers generic message", () => {
            serverFake("/foo", {
                status: "ok",
                id: 42,
                comment: "hello from outer space"
            });

            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });
            return app.send("POST", "/foo", msg, TestMsg);
        });

        it("resolves to Msg on success", () => {
            serverFake("/foo", {
                status: "ok",
                id: 42,
                comment: "hello from outer space"
            });

            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });
            return app
                .send("POST", "/foo", msg, TestMsg)
                .then((res) => {
                    assert.instanceOf(res, Msg);
                    assert.strictEqual(res.id, 42);
                    assert.strictEqual(res.comment, "hello from outer space");
                    assert.strictEqual(res.status, "ok");
                });
        });

        it("resolves to Error on failure", (done) => {
            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });
            app.send("POST", "/bar", msg, TestMsg)
                .then(() => {
                    done(new Error("should not have resolved"));
                })
                .catch((res) => {
                    assert.instanceOf(res, Error);
                    assert.strictEqual(res.message, "server returned status: 404");
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });

        it("fires send event", () => {
            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });

            serverFake("/foo", {
                status: "ok",
                id: 42,
                comment: "hello from outer space"
            });

            var p = catchEvent("webauthn-debug", eventHandler);
            function eventHandler(event) {
                if (event.detail.subtype !== "send") {
                    return false;
                }
                var data = event.detail.data;
                assert.instanceOf(data, TestMsg);
                assert.strictEqual(data.id, 12);
                return true;
            }
            app.send("POST", "/foo", msg, TestMsg);
            return p;
        });

        it("fires send-raw event", () => {
            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });

            serverFake("/foo", {
                status: "ok",
                id: 42,
                comment: "hello from outer space"
            });

            var p = catchEvent("webauthn-debug", function (event) {
                if (event.detail.subtype !== "send-raw") {
                    return;
                }
                var data = event.detail.data;
                assert.isString(data);
                return true;
            });
            app.send("POST", "/foo", msg, TestMsg);
            return p;
        });

        it("fires response-raw event on success", () => {
            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });

            serverFake("/foo", {
                status: "ok",
                id: 42,
                comment: "hello from outer space"
            });

            var p = catchEvent("webauthn-debug", function (event) {
                if (event.detail.subtype !== "response-raw") {
                    return;
                }

                var data = event.detail.data;
                assert.isObject(data);
                assert.isNumber(data.status);
                assert.isString(data.body);
                return true;
            });
            app.send("POST", "/foo", msg, TestMsg);
            return p;
        });

        it("fires response event on success", () => {
            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });

            serverFake("/foo", {
                status: "ok",
                id: 42,
                comment: "hello from outer space"
            });

            var p = catchEvent("webauthn-debug", function (event) {
                if (event.detail.subtype !== "response") {
                    return;
                }

                var data = event.detail.data;
                assert.isObject(data);
                assert.isNumber(data.status);
                assert.instanceOf(data.body, ServerResponse);
                return true;
            });
            app.send("POST", "/foo", msg, TestMsg);
            return p;
        });

        it("fires send-error event on failure", () => {
            var msg = TestMsg.from({
                id: 12,
                comment: "hi there"
            });

            // XXX: no server fake, request will fail

            var p = catchEvent("webauthn-debug", function (event) {
                if (event.detail.subtype !== "send-error") {
                    return;
                }

                var data = event.detail.data;
                assert.instanceOf(data, Error);
                return true;
            });
            app.send("POST", "/foo", msg, TestMsg).catch(() => {});
            return p;
        });
    });

    describe("requestRegisterOptions", () => {
        var serverFake = serverMock();
        var sendSpy;
        beforeEach(() => {
            sendSpy = sinon.spy(app, "send");
        });
        afterEach(() => {
            app.send.restore();
        });

        it("can get register options", () => {
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";
            return app
                .requestRegisterOptions()
                .then(() => {
                    assert.strictEqual(sendSpy.callCount, 1);
                    assert.deepEqual(
                        sendSpy.args[0],
                        [
                            "POST",
                            "/attestation/options",
                            CreateOptionsRequest.from({
                                username: "adam",
                                displayName: "adam"
                            }),
                            CreateOptions
                        ]
                    );
                });
        });

        it("resolves to correct result", () => {
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";
            return app.requestRegisterOptions()
                .then((res) => {
                    assert.instanceOf(res, CreateOptions);
                    assert.strictEqual(res.status, "ok");
                    assert.strictEqual(res.challenge, "sP4MiwodjreC8-80IMjcyWNlo_Y1SJXmFgQNBilnjdf30WRsjFDhDYmfY4-4uhq2HFjYREbXdr6Vjuvz2XvTjA==");
                });
        });
        it("rejects if username not set", (done) => {
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.requestRegisterOptions()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "expected 'username' to be 'string', got: undefined");
                    done();
                });
        });

        it("rejects on server error", (done) => {
            // XXX: no server fake
            app.username = "adam";
            app.requestRegisterOptions()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });
    });

    describe("sendRegisterResult", () => {
        var serverFake = serverMock();
        var testCred;
        var sendSpy;
        beforeEach(() => {
            sendSpy = sinon.spy(app, "send");
            // fake a PublicKeyCredential
            testCred = fido2Helpers.functions.cloneObject(fido2Helpers.lib.makeCredentialAttestationU2fResponse);
            Object.setPrototypeOf(testCred, window.PublicKeyCredential.prototype);
            // ArrayBuffers don't get copied
            testCred.rawId = fido2Helpers.lib.makeCredentialAttestationU2fResponse.rawId;
            testCred.id = undefined;
            testCred.response = fido2Helpers.lib.makeCredentialAttestationU2fResponse.response;
        });
        afterEach(() => {
            app.send.restore();
        });

        it("can get register challenge", () => {
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);
            app.username = "adam";
            return app
                .sendRegisterResult(testCred)
                .then(() => {
                    assert.strictEqual(sendSpy.callCount, 1);
                    assert.strictEqual(sendSpy.args[0][0], "POST");
                    assert.strictEqual(sendSpy.args[0][1], "/attestation/result");
                    assert.instanceOf(sendSpy.args[0][2], CredentialAttestation);
                    assert.strictEqual(sendSpy.args[0][3], ServerResponse);
                });
        });

        it("resolves to correct result", () => {
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);
            app.username = "adam";
            return app.sendRegisterResult(testCred)
                .then((res) => {
                    assert.instanceOf(res, ServerResponse);
                    assert.strictEqual(res.status, "ok");
                    assert.strictEqual(res.errorMessage, "");
                });
        });

        it("rejects if pkCred not passed in", () => {
            assert.throws(() => {
                app.sendRegisterResult();
            }, Error, "expected 'pkCred' to be instance of PublicKeyCredential");
        });

        it("rejects on server error", (done) => {
            // XXX: no server fake
            app.username = "adam";
            app.sendRegisterResult(testCred)
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });

        it("rejects on server msg failed", (done) => {
            serverFake("/attestation/result", fido2Helpers.server.errorServerResponse);
            app.username = "adam";
            app.sendRegisterResult(testCred)
                .then((res) => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "out of memory");
                    done();
                });
        });
    });

    describe("requestLoginOptions", () => {
        var serverFake = serverMock();
        var sendSpy;
        beforeEach(() => {
            sendSpy = sinon.spy(app, "send");
        });
        afterEach(() => {
            app.send.restore();
        });

        it("can get register challenge", () => {
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";
            return app
                .requestLoginOptions()
                .then(() => {
                    assert.strictEqual(sendSpy.callCount, 1);
                    assert.deepEqual(
                        sendSpy.args[0],
                        [
                            "POST",
                            "/assertion/options",
                            GetOptionsRequest.from({
                                username: "adam",
                                displayName: "adam"
                            }),
                            GetOptions
                        ]
                    );
                });
        });

        it("resolves to correct result", () => {
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";
            return app.requestLoginOptions()
                .then((res) => {
                    assert.instanceOf(res, GetOptions);
                    assert.strictEqual(res.status, "ok");
                    assert.strictEqual(res.challenge, "sP4MiwodjreC8-80IMjcyWNlo_Y1SJXmFgQNBilnjdf30WRsjFDhDYmfY4-4uhq2HFjYREbXdr6Vjuvz2XvTjA==");
                });
        });

        it("rejects if username not set", (done) => {
            serverFake("/attestation/options", fido2Helpers.server.basicGetOptions);
            app.requestLoginOptions()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "expected 'username' to be 'string', got: undefined");
                    done();
                });
        });

        it("rejects on server error", (done) => {
            // XXX: no server fake
            app.username = "adam";
            app.requestLoginOptions()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });
    });

    describe("sendLoginResult", () => {
        var serverFake = serverMock();
        var testCred;
        var sendSpy;
        beforeEach(() => {
            sendSpy = sinon.spy(app, "send");
            // fake a PublicKeyCredential
            testCred = fido2Helpers.functions.cloneObject(fido2Helpers.lib.assertionResponse);
            Object.setPrototypeOf(testCred, window.PublicKeyCredential.prototype);
            // ArrayBuffers don't get copied
            testCred.rawId = fido2Helpers.lib.assertionResponse.rawId;
            testCred.id = undefined;
            testCred.response = fido2Helpers.lib.assertionResponse.response;
        });
        afterEach(() => {
            app.send.restore();
        });

        it("can send result", () => {
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);
            app.username = "adam";
            return app
                .sendLoginResult(testCred)
                .then(() => {
                    assert.strictEqual(sendSpy.callCount, 1);
                    assert.strictEqual(sendSpy.args[0][0], "POST");
                    assert.strictEqual(sendSpy.args[0][1], "/assertion/result");
                    assert.instanceOf(sendSpy.args[0][2], CredentialAssertion);
                    assert.strictEqual(sendSpy.args[0][3], ServerResponse);
                });
        });

        it("resolves to correct result", () => {
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);
            app.username = "adam";
            return app.sendLoginResult(testCred)
                .then((res) => {
                    assert.instanceOf(res, ServerResponse);
                    assert.strictEqual(res.status, "ok");
                    assert.strictEqual(res.errorMessage, "");
                });
        });

        it("rejects if assn not passed in", () => {
            assert.throws(() => {
                app.sendLoginResult();
            }, Error, "expected 'assn' to be instance of PublicKeyCredential");
        });

        it("rejects on server error", (done) => {
            // XXX: no server fake
            app.username = "adam";
            app.sendLoginResult(testCred)
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });

        it("rejects on server msg failed", (done) => {
            serverFake("/assertion/result", fido2Helpers.server.errorServerResponse);
            app.username = "adam";
            app.sendLoginResult(testCred)
                .then((res) => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "out of memory");
                    done();
                });
        });

    });

    describe("create", () => {
        var opts = CreateOptions.from(fido2Helpers.functions.cloneObject(fido2Helpers.server.basicCreationOptions));
        var result = fido2Helpers.lib.makeCredentialAttestationU2fResponse;
        var createSpy;
        beforeEach(() => {
            createSpy = sinon.stub(navigator.credentials, "create");
            createSpy.returns(Promise.resolve(result));
        });
        afterEach(() => {
            navigator.credentials.create.restore();
        });

        it("passes with basic options", () => app.create(opts));

        it("returns promise", () => {
            var p = app.create(opts);
            assert.instanceOf(p, Promise);
        });

        it("throws when argument isn't CreateOptions", () => {
            assert.throws(() => {
                app.create({});
            }, Error, "expected 'options' to be instance of CreateOptions");
        });

        it("calls navigator.credentials.create", () => app.create(opts)
            .then((res) => {
                assert.strictEqual(createSpy.callCount, 1);
                assert.strictEqual(createSpy.args[0].length, 1);
                assert.isObject(createSpy.args[0][0]);
                var pk = createSpy.args[0][0].publicKey;
                assert.isObject(pk);
                assert.strictEqual(Object.keys(pk).length, 5);
                assert.instanceOf(pk.challenge, ArrayBuffer);
                assert.isArray(pk.pubKeyCredParams);
                assert.isObject(pk.rp);
                assert.isObject(pk.user);
                assert.strictEqual(pk.attestation, "direct");
                assert.strictEqual(res, result);
            }));

        it("fires user presence start event", () => {
            var p = catchEvent("webauthn-user-presence-start", () => true);
            app.create(opts);
            return p;
        });

        it("fires user user presence end event on success", () => {
            var p = catchEvent("webauthn-user-presence-done", () => true);
            app.create(opts);
            return p;
        });

        it("fires user user presence end event on failure", () => {
            var err = new Error("out of memory");
            createSpy.returns(Promise.reject(err));
            var p = catchEvent("webauthn-user-presence-done", () => true);
            app.create(opts).catch(() => {});
            return p;
        });

        it("fires debug event for options", () => {
            function eventHandler(event) {
                if (event.detail.subtype !== "create-options") {
                    return false;
                }
                var data = event.detail.data;
                assert.isObject(data);
                assert.strictEqual(Object.keys(data).length, 1);
                assert.isObject(data.publicKey);
                data = data.publicKey;
                assert.isObject(data.user);
                assert.isObject(data.rp);
                assert.isArray(data.pubKeyCredParams);
                assert.instanceOf(data.challenge, ArrayBuffer);
                assert.strictEqual(data.attestation, "direct");
                return true;
            }

            var p = catchEvent("webauthn-debug", eventHandler);
            app.create(opts);
            return p;
        });

        it("fires debug event for results", () => {
            function eventHandler(event) {
                if (event.detail.subtype !== "create-result") {
                    // wait for next event
                    return false;
                }
                var data = event.detail.data;
                assert.isObject(data);
                assert.isObject(data.response);
                return true;
            }

            var p = catchEvent("webauthn-debug", eventHandler);
            app.create(opts);
            return p;
        });

        it("fires debug event for error", () => {
            var err = new Error("out of memory");
            createSpy.returns(Promise.reject(err));

            function eventHandler(event) {
                if (event.detail.subtype !== "create-error") {
                    // wait for next event
                    return false;
                }
                var data = event.detail.data;
                assert.instanceOf(data, Error);
                assert.strictEqual(data.message, "out of memory");
                return true;
            }

            var p = catchEvent("webauthn-debug", eventHandler);
            app.create(opts).catch(() => {});
            return p;
        });
    });

    describe("get", () => {
        var opts = GetOptions.from(fido2Helpers.functions.cloneObject(fido2Helpers.server.basicGetOptions));
        var result = fido2Helpers.lib.assertionResponse;
        var createSpy;
        beforeEach(() => {
            createSpy = sinon.stub(navigator.credentials, "get");
            createSpy.returns(Promise.resolve(result));
        });
        afterEach(() => {
            navigator.credentials.get.restore();
        });

        it("passes with basic options", () => app.get(opts));

        it("returns promise", () => {
            var p = app.get(opts);
            assert.instanceOf(p, Promise);
        });

        it("throws when argument isn't GetOptions", () => {
            assert.throws(() => {
                app.get({});
            }, Error, "expected 'options' to be instance of GetOptions");
        });

        it("calls navigator.credentials.get", () => app.get(opts)
            .then((res) => {
                assert.strictEqual(createSpy.callCount, 1);
                assert.strictEqual(createSpy.args[0].length, 1);
                assert.isObject(createSpy.args[0][0]);
                var pk = createSpy.args[0][0].publicKey;
                assert.isObject(pk);
                assert.strictEqual(Object.keys(pk).length, 1);
                assert.instanceOf(pk.challenge, ArrayBuffer);
                assert.strictEqual(res, result);
            }));

        it("fires user presence start event", () => {
            var p = catchEvent("webauthn-user-presence-start", () => true);
            app.get(opts);
            return p;
        });

        it("fires user user presence end event on success", () => {
            var p = catchEvent("webauthn-user-presence-done", () => true);
            app.get(opts);
            return p;
        });

        it("fires user user presence end event on failure", () => {
            var err = new Error("out of memory");
            createSpy.returns(Promise.reject(err));
            var p = catchEvent("webauthn-user-presence-done", () => true);
            app.get(opts).catch(() => {});
            return p;
        });

        it("fires debug event for options", () => {
            function eventHandler(event) {
                if (event.detail.subtype !== "get-options") {
                    // wait for next event
                    return false;
                }
                var data = event.detail.data;
                assert.isObject(data);
                assert.strictEqual(Object.keys(data).length, 1);
                assert.isObject(data.publicKey);
                data = data.publicKey;
                assert.instanceOf(data.challenge, ArrayBuffer);
                return true;
            }

            var p = catchEvent("webauthn-debug", eventHandler);
            app.get(opts);
            return p;
        });

        it("fires debug event for results", () => {
            function eventHandler(event) {
                if (event.detail.subtype !== "get-result") {
                    // wait for next event
                    return false;
                }
                var data = event.detail.data;
                assert.isObject(data);
                assert.isObject(data.response);
                return true;
            }

            var p = catchEvent("webauthn-debug", eventHandler);
            app.get(opts);
            return p;
        });

        it("fires debug event for error", () => {
            var err = new Error("out of memory");
            createSpy.returns(Promise.reject(err));

            function eventHandler(event) {
                if (event.detail.subtype !== "get-error") {
                    // wait for next event
                    return false;
                }
                var data = event.detail.data;
                assert.instanceOf(data, Error);
                assert.strictEqual(data.message, "out of memory");
                return true;
            }

            var p = catchEvent("webauthn-debug", eventHandler);
            app.get(opts).catch(() => {});
            return p;
        });
    });

    describe("register", () => {
        var serverFake = serverMock();
        var createMock;
        beforeEach(() => {
            var testCred = fido2Helpers.functions.cloneObject(fido2Helpers.lib.makeCredentialAttestationU2fResponse);
            Object.setPrototypeOf(testCred, window.PublicKeyCredential.prototype);
            // ArrayBuffers don't get copied
            testCred.rawId = fido2Helpers.lib.makeCredentialAttestationU2fResponse.rawId;
            testCred.id = undefined;
            testCred.response = fido2Helpers.lib.makeCredentialAttestationU2fResponse.response;
            createMock = sinon.stub(navigator.credentials, "create");
            createMock.returns(Promise.resolve(testCred));
        });

        afterEach(() => {
            navigator.credentials.create.restore();
        });

        it("returns promise", () => {
            var p = app.register().catch(() => {});
            assert.instanceOf(p, Promise);
        });

        it("can complete registration", () => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            return app.register();
        });

        it("resolves to true", () => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            return app.register()
                .then((res) => {
                    assert.isObject(res);
                    assert.instanceOf(res, ServerResponse);
                    assert.strictEqual(res.status, "ok");
                    assert.strictEqual(res.errorMessage, "");
                });
        });

        it("fails on failed option request", (done) => {
            // options
            // serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            app.register()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                });
        });

        it("fails on failed cred create", (done) => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.basicCreationOptions);

            // get
            createMock.returns(Promise.reject(new Error("hamsters too tired")));

            return app.register()
                .then((res) => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "hamsters too tired");
                    done();
                });
        });

        it("fails on failed result", (done) => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            // serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            app.register()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                });
        });

        it("fails on status: failed from server", (done) => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.errorServerResponse);

            app.register()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "out of memory");
                    done();
                });
        });

        it("fires webauthn-register-start", () => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-register-start", () => true);
            app.register();
            return p;
        });

        it("fires webauthn-register-done on success", () => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-register-done", () => true);
            app.register();
            return p;
        });

        it("fires webauthn-register-error", () => {
            // options
            // serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-register-error", (err) => {
                assert.instanceOf(err.detail, Error);
                assert.strictEqual(err.detail.message, "server returned status: 404");
                return true;
            });
            app.register().catch(() => {});
            return p;
        });

        it("fires webauthn-register-success", () => {
            // options
            serverFake("/attestation/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/attestation/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-register-success", () => true);
            app.register();
            return p;
        });
    });

    describe("login", () => {
        var serverFake = serverMock();
        var getMock;
        beforeEach(() => {
            var testCred = fido2Helpers.functions.cloneObject(fido2Helpers.lib.assertionResponse);
            Object.setPrototypeOf(testCred, window.PublicKeyCredential.prototype);
            // ArrayBuffers don't get copied
            testCred.rawId = fido2Helpers.lib.assertionResponse.rawId;
            testCred.id = undefined;
            testCred.response = fido2Helpers.lib.assertionResponse.response;
            getMock = sinon.stub(navigator.credentials, "get");
            getMock.returns(Promise.resolve(testCred));
        });

        afterEach(() => {
            navigator.credentials.get.restore();
        });

        it("returns promise", () => {
            var p = app.login().catch(() => {});
            assert.instanceOf(p, Promise);
        });

        it("can complete login", () => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            return app.login();
        });

        it("resolves to true", () => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            return app.login()
                .then((res) => {
                    assert.isObject(res);
                    assert.instanceOf(res, ServerResponse);
                    assert.strictEqual(res.status, "ok");
                    assert.strictEqual(res.errorMessage, "");
                });
        });

        it("fails on failed option request", (done) => {
            // options
            // serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            app.login()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                });
        });

        it("fails on failed cred get", (done) => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.basicCreationOptions);

            // get
            getMock.returns(Promise.reject(new Error("hamsters too tired")));

            return app.login()
                .then((res) => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "hamsters too tired");
                    done();
                });
        });

        it("fails on failed result", (done) => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            // serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            app.login()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "server returned status: 404");
                    done();
                });
        });

        it("fails on status: failed from server", (done) => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.errorServerResponse);

            app.login()
                .then(() => {
                    done(new Error("should have rejected"));
                })
                .catch((err) => {
                    assert.instanceOf(err, Error);
                    assert.strictEqual(err.message, "out of memory");
                    done();
                });
        });

        it("fires webauthn-login-start", () => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-login-start", () => true);
            app.login();
            return p;
        });

        it("fires webauthn-login-done on success", () => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-login-done", () => true);
            app.login();
            return p;
        });

        it("fires webauthn-login-error", () => {
            // options
            // serverFake("/assertion/options", fido2Helpers.server.basicCreationOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-login-error", (err) => {
                assert.instanceOf(err.detail, Error);
                assert.strictEqual(err.detail.message, "server returned status: 404");
                return true;
            });
            app.login().catch(() => {});
            return p;
        });

        it("fires webauthn-login-success", () => {
            // options
            serverFake("/assertion/options", fido2Helpers.server.basicGetOptions);
            app.username = "adam";

            // result
            serverFake("/assertion/result", fido2Helpers.server.successServerResponse);

            var p = catchEvent("webauthn-login-success", () => true);
            app.login();
            return p;
        });
    });
});
