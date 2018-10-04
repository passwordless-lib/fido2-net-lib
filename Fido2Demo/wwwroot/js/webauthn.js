function markPlatformAuthenticatorUnavailable() {

    var authenticator_attachment = $('#select-authenticator').find(':selected').val();
    var user_verification = $('#select-userVerification').find(':selected').val();

    if (authenticator_attachment === "platform" && user_verification === "required") {
        showWarningAlert("User verifying platform authenticators are not currently supported by this browser");
    }
}

function detectFIDOSupport() {
    if (window.PublicKeyCredential === undefined ||
        typeof window.PublicKeyCredential !== "function") {
        $('#register-button').attr("disabled", true);
        $('#login-button').attr("disabled", true);
        showErrorAlert("WebAuthn is not currently supported by this browser");
        return;
    }
}

function detectFIDOUserVerifyingPlatformSupport() {
    if (window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
        markPlatformAuthenticatorUnavailable();
    } else if (typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === "function") {
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(function (available) {
            if (!available) {
                markPlatformAuthenticatorUnavailable();
            }
        }).catch(function (e) {
            markPlatformAuthenticatorUnavailable();
        });
    }
}


function hexEncode(buf) {
    return Array.from(buf)
        .map(function (x) {
            return ("0" + x.toString(16)).substr(-2)
        })
        .join("");
}

function hexDecode(str) {
    return new Uint8Array(str.match(/../g).map(function (x) { return parseInt(x, 16) }));
}

function b64enc(buf) {
    return coerceToBase64Url(buf, "something");
    //return base64js.fromByteArray(buf)
    //    .replace(/\+/g, "-")
    //    .replace(/\//g, "_")
    //    .replace(/=/g, "");
}

coerceToBase64Url = function (thing, name) {
    // Array or ArrayBuffer to Uint8Array
    if (Array.isArray(thing)) {
        thing = Uint8Array.from(thing);
    }

    if (thing instanceof ArrayBuffer) {
        thing = new Uint8Array(thing);
    }

    // Uint8Array to base64
    if (thing instanceof Uint8Array) {
        var str = "";
        var len = thing.byteLength;

        for (var i = 0; i < len; i++) {
            str += String.fromCharCode(thing[i]);
        }
        thing = window.btoa(str);
    }

    if (typeof thing !== "string") {
        throw new Error("could not coerce '" + name + "' to string");
    }

    // base64 to base64url
    // NOTE: "=" at the end of challenge is optional, strip it off here
    thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");

    return thing;
};

coerceToArrayBuffer = function (thing, name) {
    if (typeof thing === "string") {
        // base64url to base64
        thing = thing.replace(/-/g, "+").replace(/_/g, "/");

        // base64 to Uint8Array
        var str = window.atob(thing);
        var bytes = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) {
            bytes[i] = str.charCodeAt(i);
        }
        thing = bytes;
    }

    // Array to Uint8Array
    if (Array.isArray(thing)) {
        thing = new Uint8Array(thing);
    }

    // Uint8Array to ArrayBuffer
    if (thing instanceof Uint8Array) {
        thing = thing.buffer;
    }

    // error if none of the above worked
    if (!(thing instanceof ArrayBuffer)) {
        throw new TypeError("could not coerce '" + name + "' to ArrayBuffer");
    }

    return thing;
};

// Don't drop any blanks
function b64RawEnc(buf) {
    return b64enc(buf);
    //return base64js.fromByteArray(buf)
    //    //.replace(/\+/g, "-")
    //    //.replace(/\//g, "_")
    //    .replace(/\+/g, "-")
    //    .replace(/\//g, "_")
    //    .replace(/=*$/g, "")
}

function string2buffer(str) {
    return (new Uint8Array(str.length)).map(function (x, i) {
        return str.charCodeAt(i)
    });
}

function buffer2string(buf) {
    let str = "";
    if (!(buf.constructor === Uint8Array)) {
        buf = new Uint8Array(buf);
    }
    buf.map(function (x) { return str += String.fromCharCode(x) });
    return str;
}

var state = {
    createResponse: null,
    publicKeyCredential: null,
    credential: null,
    user: {
        name: "testuser@example.com",
        displayName: "testuser",
    },
}

function setUser() {
    username = $("#input-email").val();
    state.user.name = username.toLowerCase().replace(/\s/g, '') + "@example.com";
    state.user.displayName = username.toLowerCase();
}

function checkUserExists() {
    $.get('/user/' + state.user.name, {}, null, 'json')
        .done(function (response) {
            return true;
        }).catch(function () { return false; });
}

function getCredentials() {
    $.get('/credential/' + state.user.name, {}, null, 'json')
        .done(function (response) {
            console.log(response)
        });
}

function makeCredential() {
    hideErrorAlert();
    console.log("Fetching options for new credential");
    if ($("#input-email").val() === "") {
        showErrorAlert("Please enter a username");
        return;
    }
    setUser();

    var attestation_type = $('#select-attestation').find(':selected').val();
    var authenticator_attachment = $('#select-authenticator').find(':selected').val();
    var user_verification = $('#select-userVerification').find(':selected').val();
    var require_resident_key = $("#checkbox-residentCredentials").is(':checked');

    var data = new FormData();
    data.append('username', state.user.name);
    data.append('attType', attestation_type);
    data.append('authType', authenticator_attachment);
    data.append('userVerifcation', user_verification);
    data.append('requireResidentKey', require_resident_key);

    fetch('/makeCredentialOptions', {
        method: 'POST', // or 'PUT'
        body: data, // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json',
        }
    }).then((response) => {
        if (response.ok) {
            return response.json();
        }
        return Promise.reject(response.text());
    })
        .catch((error) => {
            error.then(msg => showErrorAlert(msg));
        })
        .then((makeCredentialOptions) => {
            console.log("Credential Options Object");
            console.log(makeCredentialOptions);

            if (makeCredentialOptions.status !== "ok") {
                console.log("Error creating credential options");
                console.log(makeCredentialOptions.errorMessage);
                showErrorAlert(makeCredentialOptions.errorMessage);
                return;
            }

            // base64url to base64
            //const challenge = makeCredentialOptions.challenge.replace(/-/g, "+").replace(/_/g, "/");

            // Turn the challenge back into the accepted format
            makeCredentialOptions.challenge = coerceToArrayBuffer(makeCredentialOptions.challenge); // Uint8Array.from(atob(challenge), c => c.charCodeAt(0));
            // Turn ID into a UInt8Array Buffer for some reason
            makeCredentialOptions.user.id = coerceToArrayBuffer(makeCredentialOptions.user.id);

            makeCredentialOptions.excludeCredentials = makeCredentialOptions.excludeCredentials.map((c) => {
                c.id = coerceToArrayBuffer(c.id);
                return c;
            });

            if (makeCredentialOptions.authenticatorSelection.authenticatorAttachment === null) makeCredentialOptions.authenticatorSelection.authenticatorAttachment = undefined;

            console.log("Credential Options Formatted");
            console.log(makeCredentialOptions);

            swal({
                title: 'Registering...',
                text: 'Tap your security key to finish registration.',
                imageUrl: "/images/securitykey.min.svg",
                showCancelButton: true,
                showConfirmButton: false,
                focusConfirm: false,
                focusCancel: false,
            }).then(function (result) {
                if (!result.value) {
                    console.log('Registration cancelled');
                }
            }).catch(function (error) {
                console.log("Modal Error: " + error);
            });

            console.log("Creating PublicKeyCredential");
            navigator.credentials.create({
                publicKey: makeCredentialOptions
            }).then(function (newCredential) {
                console.log("PublicKeyCredential Created");
                console.log(newCredential);
                state.createResponse = newCredential;
                registerNewCredential(newCredential);
            }).catch(function (err) {
                console.log(err);
                swal.closeModal();
                showErrorAlert(err.message ? err.message : err);
            });
        });
}

// This should be used to verify the auth data with the server
function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);

    const data = {
        id: newCredential.id,
        rawId: b64enc(rawId),
        type: newCredential.type,
        response: {
            AttestationObject: b64RawEnc(attestationObject),
            clientDataJson: b64RawEnc(clientDataJSON)
        }
    };

    fetch('/makeCredential', {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(data), // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    }).then(res => res.json())
        .catch(error => console.error('Error:', error))
        //.then(response => console.log('Success:', response))
        .then(response => {
            console.log("Credential Object");
            console.log(response);

            if (response.status !== "ok") {
                console.log("Error creating credential");
                console.log(response.errorMessage);
                swal.closeModal();
                showErrorAlert(response.errorMessage);
                return;
            }

            swal({
                title: 'Registration Successful!',
                text: 'You\'ve registered successfully.',
                type: 'success',
                timer: 2000
            });
            //window.location.href = "/dashboard/" + state.user.displayName;
        });
}

function addUserErrorMsg(msg) {
    if (msg === "username") {
        msg = 'Please add username';
    } else {
        msg = 'Please add email';
    }
    document.getElementById("user-create-error").innerHTML = msg;
}

function getAssertion() {
    hideErrorAlert();
    if ($("#input-email").val() === "") {
        showErrorAlert("Please enter a username");
        return;
    }
    setUser();
    var data = new FormData();
    data.append('username', state.user.name);

    fetch('/assertionOptions', {
        method: 'POST', // or 'PUT'
        body: data, // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json',
        }
    }).then((response) => {
        if (response.ok) {
            return response.json();
        }
        return Promise.reject(response.text());
    })
        .catch((error) => {
            error.then(msg => showErrorAlert(msg));
        })
        .then((makeAssertionOptions) => {
            console.log("Assertion Options Object");
            console.log(makeAssertionOptions);

            if (makeAssertionOptions.status !== "ok") {
                console.log("Error creating assertion options");
                console.log(makeAssertionOptions.errorMessage);
                showErrorAlert(makeAssertionOptions.errorMessage);
                return;
            }

            const challenge = makeAssertionOptions.challenge.replace(/-/g, "+").replace(/_/g, "/");
            makeAssertionOptions.challenge = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));

            makeAssertionOptions.allowCredentials.forEach(function (listItem) {
                var fixedId = listItem.id.replace(/\_/g, "/").replace(/\-/g, "+")
                listItem.id = Uint8Array.from(atob(fixedId), c => c.charCodeAt(0));
            });
            console.log(makeAssertionOptions);

            swal({
                title: 'Logging In...',
                text: 'Tap your security key to login.',
                imageUrl: "/images/securitykey.min.svg",
                showCancelButton: true,
                showConfirmButton: false,
                focusConfirm: false,
                focusCancel: false,
            }).then(function (result) {
                if (!result.value) {
                    console.log('Login cancelled');
                }
            }).catch(function (error) {
                console.log("Modal Error: " + error);
            });

            navigator.credentials.get({ publicKey: makeAssertionOptions })
                .then(function (credential) {
                    console.log(credential);
                    verifyAssertion(credential);
                }).catch(function (err) {
                    console.log(err);
                    showErrorAlert(err.message ? err.message : err);
                    swal.closeModal();
                });
        });
}

function verifyAssertion(assertedCredential) {
    // Move data into Arrays incase it is super long
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    const data = {
        id: assertedCredential.id,
        rawId: b64enc(rawId),
        type: assertedCredential.type,
        response: {
            authenticatorData: b64RawEnc(authData),
            clientDataJson: b64RawEnc(clientDataJSON),
            signature: b64RawEnc(sig)
        }
    };

    fetch("/makeAssertion", {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(data), // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    })
        .then(res => res.json())
        .catch(error => console.error('Error:', error))
        .then((response) => {
            console.log("Assertion Object");
            console.log(response);

            if (response.status !== "ok") {
                console.log("Error doing assertion");
                console.log(response.errorMessage);
                swal.closeModal();
                showErrorAlert(response.errorMessage);
                return;
            }

            swal({
                title: 'Logged In!',
                text: 'You\'re logged in successfully.',
                type: 'success',
                timer: 2000
            });
            //window.location.href = "/dashboard/" + state.user.displayName;
        });
}

function setCurrentUser(userResponse) {
    state.user.name = userResponse.name;
    state.user.displayName = userResponse.display_name;
}

function showErrorAlert(msg) {
    $("#alert-msg").text(msg);
    $("#user-alert").show();
}

function showWarningAlert(msg) {
    $("#warning-msg").text(msg);
    $("#user-warning").show();
}

function hideWarningAlert() {
    $("#user-warning").fadeOut(200);
}

function showSuccessAlert(msg) {
    swal()
}

function hideErrorAlert() {
    $("#user-alert").hide();
}

if (window.location.protocol !== "https:") {
    showErrorAlert("Please use HTTPS");
}