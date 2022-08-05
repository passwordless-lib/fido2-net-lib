document.getElementById('signin').addEventListener('submit', handleSignInSubmit);

async function handleSignInSubmit(event) {
    event.preventDefault();

    let username = this.username.value;

    // passwordfield is omitted in demo
    // let password = this.password.value;


    // prepare form post data
    var formData = new FormData();
    formData.append('username', username);

    // not done in demo
    // todo: validate username + password with server (has nothing to do with FIDO2/WebAuthn)

    // send to server for registering
    let makeAssertionOptions;
    try {
        // use jquery ajax instead of fetch because of safari browser and platform authenticator
        // https://github.com/passwordless-lib/fido2-net-lib/issues/303
        makeAssertionOptions = await $.post({
            url: '/assertionOptions',
            type: 'POST',
            data: formData,
            processData: false,
            contentType: false,
        }, 'json');
    } catch (e) {
        showErrorAlert("Request to server failed", e);
    }

    console.log("Assertion Options Object", makeAssertionOptions);

    // show options error to user
    if (makeAssertionOptions.status !== "ok") {
        console.log("Error creating assertion options");
        console.log(makeAssertionOptions.errorMessage);
        showErrorAlert(makeAssertionOptions.errorMessage);
        return;
    }

    // todo: switch this to coercebase64
    const challenge = makeAssertionOptions.challenge.replace(/-/g, "+").replace(/_/g, "/");
    makeAssertionOptions.challenge = Uint8Array.from(atob(challenge), c => c.charCodeAt(0));

    // fix escaping. Change this to coerce
    makeAssertionOptions.allowCredentials.forEach(function (listItem) {
        var fixedId = listItem.id.replace(/\_/g, "/").replace(/\-/g, "+");
        listItem.id = Uint8Array.from(atob(fixedId), c => c.charCodeAt(0));
    });

    console.log("Assertion options", makeAssertionOptions);

    Swal.fire({
        title: 'Logging In...',
        text: 'Tap your security key to login.',
        imageUrl: "/images/securitykey.min.svg",
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });

    // ask browser for credentials (browser will ask connected authenticators)
    let credential;
    try {
        credential = await navigator.credentials.get({ publicKey: makeAssertionOptions })
    } catch (err) {
        showErrorAlert(err.message ? err.message : err);
    }

    try {
        await verifyAssertionWithServer(credential);
    } catch (e) {
        showErrorAlert("Could not verify assertion", e);
    }
}

/**
 * Sends the credential to the the FIDO2 server for assertion
 * @param {any} assertedCredential
 */
async function verifyAssertionWithServer(assertedCredential) {

    // Move data into Arrays incase it is super long
    let authData = new Uint8Array(assertedCredential.response.authenticatorData);
    let clientDataJSON = new Uint8Array(assertedCredential.response.clientDataJSON);
    let rawId = new Uint8Array(assertedCredential.rawId);
    let sig = new Uint8Array(assertedCredential.response.signature);
    const data = {
        id: assertedCredential.id,
        rawId: coerceToBase64Url(rawId),
        type: assertedCredential.type,
        extensions: assertedCredential.getClientExtensionResults(),
        response: {
            authenticatorData: coerceToBase64Url(authData),
            clientDataJson: coerceToBase64Url(clientDataJSON),
            signature: coerceToBase64Url(sig)
        }
    };

    let response;
    try {
      let res = await fetch("/makeAssertion", {
            method: 'POST', // or 'PUT'
            body: JSON.stringify(data), // data can be `string` or {object}!
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
        });

        response = await res.json();
    } catch (e) {
        showErrorAlert("Request to server failed", e);
        throw e;
    }

    console.log("Assertion Object", response);

    // show error
    if (response.status !== "ok") {
        console.log("Error doing assertion");
        console.log(response.errorMessage);
        showErrorAlert(response.errorMessage);
        return;
    }

    // show success message
    await Swal.fire({
        title: 'Logged In!',
        text: 'You\'re logged in successfully.',
        type: 'success',
        timer: 2000
    });


    // redirect to dashboard to show keys
    window.location.href = "/dashboard/" + value("#login-username");
}
