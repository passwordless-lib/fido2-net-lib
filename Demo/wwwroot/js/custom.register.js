document.getElementById('register').addEventListener('submit', handleRegisterSubmit);

async function handleRegisterSubmit(event) {
    event.preventDefault();

    let username = this.username.value;
    let displayName = this.displayName.value;

    let attestation_type = "none";

    if (value('#option-attestation') !== "undefined") {
        attestation_type = value('#option-attestation');
    }

    let authenticator_attachment = "";

    if (value("#option-authenticator") !== "undefined") {
        authenticator_attachment = value("#option-authenticator");
    }

    let user_verification = "discouraged";

    if (value("#option-userverification") !== "undefined") {
        user_verification = value("#option-userverification");
    }

    let require_resident_key = value("#option-residentkey");

    // prepare form post data
    var data = new FormData();
    data.append('username', username);
    data.append('displayName', displayName);
    data.append('attType', attestation_type);
    data.append('authType', authenticator_attachment);
    data.append('userVerification', user_verification);
    data.append('requireResidentKey', require_resident_key);

    try {
        makeCredentialOptions = await fetchMakeCredentialOptions(data);

    } catch (e) {
        console.error(e);
        let msg = "Something wen't really wrong";
        showErrorAlert(msg);
    }


    console.log("Credential Options Object", makeCredentialOptions);

    if (makeCredentialOptions.status !== "ok") {
        console.log("Error creating credential options");
        console.log(makeCredentialOptions.errorMessage);
        showErrorAlert(makeCredentialOptions.errorMessage);
        return;
    }

    // Turn the challenge back into the accepted format of padded base64
    makeCredentialOptions.challenge = coerceToArrayBuffer(makeCredentialOptions.challenge);
    // Turn ID into a UInt8Array Buffer for some reason
    makeCredentialOptions.user.id = coerceToArrayBuffer(makeCredentialOptions.user.id);

    makeCredentialOptions.excludeCredentials = makeCredentialOptions.excludeCredentials.map((c) => {
        c.id = coerceToArrayBuffer(c.id);
        return c;
    });

    if (makeCredentialOptions.authenticatorSelection.authenticatorAttachment === null) makeCredentialOptions.authenticatorSelection.authenticatorAttachment = undefined;

    console.log("Credential Options Formatted", makeCredentialOptions);

    // send to server for registering
    var makeCredentialOptions = {
        rp: {
            name: "WebAuthn Test Server",
            icon: "https://example.com/rpIcon.png"
        },
        user: {
            id: makeCredentialOptions.user.id,
            name: displayName,
            user: displayName,
            displayName: displayName,
            icon: "https://example.com/userIcon.png"
        },
        challenge: makeCredentialOptions.challenge,
        pubKeyCredParams: [],
        timeout: 90000,
        excludeCredentials: [],
        authenticatorSelection: {
            userVerification: "discouraged"
        },
        attestation: undefined,
        extensions: {}
    };

    switch (value('#option-rpinfo')) {
        case "normal":
            makeCredentialOptions.rp.id = window.location.hostname;
            break;
        case "suffix":
            makeCredentialOptions.rp.id = "suffix." + window.location.hostname;
            break;
        case "securityerror":
            makeCredentialOptions.rp.id = "foo.com";
            break;
        case "emptyrpid":
            makeCredentialOptions.rp.id = "";
            break;
        case "emptyrpname":
            makeCredentialOptions.rp.name = undefined;
            break;
        case "emptyrpicon":
            makeCredentialOptions.rp.icon = undefined;
        case "undefined":
        default:
            break;
    }

    if (value('#option-ES256')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -7
        });
    }
    if (value('#option-ES384')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -35
        });
    }
    if (value('#option-ES512')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -36
        });
    }
    if (value('#option-RS256')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -257
        });
    }
    if (value('#option-RS384')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -258
        });
    }
    if (value('#option-RS512')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -259
        });
    }
    if (value('#option-PS256')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -37
        });
    }
    if (value('#option-PS384')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -38
        });
    }
    if (value('#option-PS512')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -39
        });
    }
    if (value('#option-EdDSA')) {
        makeCredentialOptions.pubKeyCredParams.push({
            type: "public-key",
            alg: -8
        });
    }

    if (value('#option-attestation') !== "undefined") {
        makeCredentialOptions.attestation = value('#option-attestation');
    }

    if (value('#option-requireresidentkey') !== "undefined") {
        var requireResidentKey = (value('#option-requireresidentkey') == "true");
        makeCredentialOptions.authenticatorSelection.requireResidentKey = requireResidentKey;
    }

    if (value('#option-residentkey') !== "undefined") {
        makeCredentialOptions.authenticatorSelection.residentKey = value('#option-residentkey');
    }

    if (value('#option-credprotect') !== "undefined") {
        var credProtect = value('#option-credprotect');
        makeCredentialOptions.extensions.credentialProtectionPolicy = credProtect;
    }

    if (value('#option-credprotectenforce') !== "undefined") {
        var enforceCredProtect = (value('#coption-credprotectenforce') == "true");
        makeCredentialOptions.extensions.enforceCredentialProtectionPolicy = enforceCredProtect;
    }

    if (value('#option-hmaccreate') !== "undefined") {
        var hmacCreateSecret = (value('#option-hmaccreate') == "true");
        makeCredentialOptions.extensions.hmacCreateSecret = hmacCreateSecret;
    }

    if (value('#option-minPinLength') !== "undefined") {
        var minPinLength = (value('#option-minPinLength') == "true");
        makeCredentialOptions.extensions.minPinLength = minPinLength;
    }

    if (value('#option-largeBlob') !== "undefined") {
        makeCredentialOptions.extensions.largeBlob = {};
        makeCredentialOptions.extensions.largeBlob.support = value('#option-largeBlob');
    }

    if (value("#option-userverification") !== "undefined") {
        makeCredentialOptions.authenticatorSelection.userVerification = value("#option-userverification");
    }

    Swal.fire({
        title: 'Registering...',
        text: 'Tap your security key to finish registration.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });


    console.log("Creating PublicKeyCredential...");

    let newCredential;
    try {
        newCredential = await navigator.credentials.create({
            publicKey: makeCredentialOptions
        });
    } catch (e) {
        var msg = "Could not create credentials in browser. Probably because the username is already registered with your authenticator. Please change username or authenticator."
        console.error(msg, e);
        showErrorAlert(msg, e);
    }


    console.log("PublicKeyCredential Created", newCredential);

    try {
        registerNewCredential(newCredential);
    } catch (err) {
        showErrorAlert(err.message ? err.message : err);
    }
}

async function fetchMakeCredentialOptions(formData) {
    // use jquery ajax instead of fetch because of safari browser and platform authenticator
    // https://github.com/passwordless-lib/fido2-net-lib/issues/303
    return await $.post({
        url: '/makeCredentialOptions',
        type: 'POST',
        data: formData,
        processData: false,
        contentType: false,
    }, 'json');
}

// This should be used to verify the auth data with the server
async function registerNewCredential(newCredential) {
    // Move data into Arrays incase it is super long
    let attestationObject = new Uint8Array(newCredential.response.attestationObject);
    let clientDataJSON = new Uint8Array(newCredential.response.clientDataJSON);
    let rawId = new Uint8Array(newCredential.rawId);

    const data = {
        id: newCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: newCredential.type,
        extensions: newCredential.getClientExtensionResults(),
        response: {
            AttestationObject: coerceToBase64Url(attestationObject),
            clientDataJson: coerceToBase64Url(clientDataJSON)
        }
    };

    let response;
    try {
            response = await registerCredentialWithServer(data);
        } catch (e) {
            showErrorAlert(e);
    }

            console.log("Credential Object", response);

            // show error
            if (response.status !== "ok") {
                console.log("Error creating credential");
                console.log(response.errorMessage);
                showErrorAlert(response.errorMessage);
                return;
            }

            // show success 
            Swal.fire({
                title: 'Registration Successful!',
                text: 'You\'ve registered successfully.',
                type: 'success',
                timer: 2000
            });
 
    // redirect to dashboard?
    //window.location.href = "/dashboard/" + state.user.displayName;
}

async function registerCredentialWithServer(formData) {
    let response = await fetch('/makeCredential', {
        method: 'POST', // or 'PUT'
        body: JSON.stringify(formData), // data can be `string` or {object}!
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
    });

    let data = await response.json();

    return data;
}
