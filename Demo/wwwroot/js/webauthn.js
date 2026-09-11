// Shared WebAuthn ceremony code for the demo pages.
//
// Each scenario page (mfa, passwordless, usernameless, custom) supplies only the options that make that
// scenario what it is; everything below is common to all four. Read your page's own .register.js/.login.js
// first -- it is short -- then come back here for the ceremony itself.

// ---------------------------------------------------------------------------------------------------
// Transport helpers
// ---------------------------------------------------------------------------------------------------

async function postForm(url, fields) {
    const body = new FormData();
    for (const [key, value] of Object.entries(fields)) {
        if (value !== undefined && value !== null && value !== '') {
            body.append(key, value);
        }
    }

    const response = await fetch(url, { method: 'POST', body, headers: { 'Accept': 'application/json' } });
    return await response.json();
}

async function postJson(url, payload) {
    const response = await fetch(url, {
        method: 'POST',
        body: JSON.stringify(payload),
        headers: { 'Accept': 'application/json', 'Content-Type': 'application/json' }
    });
    return await response.json();
}

/** The demo's controllers report failures as { status: 'error', errorMessage }. */
function isServerError(result) {
    return result && result.status === 'error';
}

/**
 * True when the user simply dismissed the browser's prompt, rather than anything going wrong. Worth
 * separating: telling someone "the username is already registered" when they pressed Escape is misleading.
 */
function isUserCancellation(error) {
    return error && (error.name === 'NotAllowedError' || error.name === 'AbortError');
}

// ---------------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------------

/**
 * Runs a full registration ceremony.
 *
 * @param {object} config
 *   username, displayName          - the account being registered
 *   attestation                    - none | indirect | direct | enterprise
 *   authenticatorAttachment        - '' | platform | cross-platform
 *   userVerification               - required | preferred | discouraged
 *   residentKey                    - required | preferred | discouraged
 *   hints                          - WebAuthn L3 §5.8.8, e.g. ['security-key']
 *   attestationFormats             - WebAuthn L3 §5.4, e.g. ['packed']
 *   prf                            - request the prf extension (L3 §10.1.4)
 *   mediation                      - 'conditional' performs a conditional create (L3 §5.1.3)
 */
async function registerCeremony(config) {
    let options;
    try {
        options = await postForm('/makeCredentialOptions', {
            username: config.username,
            displayName: config.displayName,
            attType: config.attestation,
            authType: config.authenticatorAttachment,
            userVerification: config.userVerification,
            residentKey: config.residentKey,
            hints: (config.hints || []).join(','),
            attestationFormats: (config.attestationFormats || []).join(','),
            prf: config.prf ? 'true' : ''
        });
    } catch (e) {
        console.error(e);
        showErrorAlert('Could not reach the server to start registration.', e);
        return;
    }

    console.log('Credential Options Object', options);

    if (isServerError(options)) {
        showErrorAlert(options.errorMessage);
        return;
    }

    // WebAuthn L3 §5.1.8: the server speaks the JSON form of the options, the browser turns it into the
    // ArrayBuffer-bearing dictionary that create() wants.
    options = PublicKeyCredential.parseCreationOptionsFromJSON(options);

    console.log('Credential Options Formatted', options);

    Swal.fire({
        title: 'Registering...',
        text: 'Tap your security key to finish registration.',
        imageUrl: '/images/securitykey.min.svg',
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });

    let newCredential;
    try {
        const request = { publicKey: options };

        // A conditional create is offered quietly by the browser rather than in a modal prompt, so no user
        // presence test happens and the UP flag is not set. The server has to be told, or it rejects the
        // response for the missing flag.
        if (config.mediation) {
            request.mediation = config.mediation;
        }

        newCredential = await navigator.credentials.create(request);
    } catch (e) {
        console.error('create() failed', e);
        if (isUserCancellation(e)) {
            Swal.close();
        } else {
            showErrorAlert('Could not create a credential. The username may already be registered with this '
                + 'authenticator -- try a different username or authenticator.', e);
        }
        return;
    }

    if (!newCredential) {
        Swal.close();
        return;
    }

    console.log('PublicKeyCredential Created', newCredential);

    let result;
    try {
        // WebAuthn L3 §5.1: toJSON() gives the base64url-encoded form the server model expects.
        const query = config.mediation ? '?mediation=' + encodeURIComponent(config.mediation) : '';
        result = await postJson('/makeCredential' + query, newCredential.toJSON());
    } catch (e) {
        showErrorAlert('Could not send the new credential to the server.', e);
        return;
    }

    console.log('Credential Object', result);

    if (isServerError(result)) {
        showErrorAlert(result.errorMessage);
        return;
    }

    await Swal.fire({
        title: 'Registration Successful!',
        text: 'You\'ve registered successfully.',
        icon: 'success',
        timer: 2000
    });

    // The usernameless flow has no username to redirect with -- the server generated the account name --
    // so prefer the name it echoes back on the credential.
    const registeredName = (result.user && result.user.name) || config.username;
    if (registeredName) {
        window.location.href = '/dashboard/' + encodeURIComponent(registeredName);
    }
}

// ---------------------------------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------------------------------

/**
 * Runs a full authentication ceremony.
 *
 * @param {object} config
 *   username         - omit for a usernameless (discoverable credential) sign-in
 *   userVerification - required | preferred | discouraged
 *   hints            - WebAuthn L3 §5.8.8
 */
async function signInCeremony(config) {
    let options;
    try {
        options = await postForm('/assertionOptions', {
            username: config.username,
            userVerification: config.userVerification,
            hints: (config.hints || []).join(',')
        });
    } catch (e) {
        console.error(e);
        showErrorAlert('Could not reach the server to start sign-in.', e);
        return;
    }

    console.log('Assertion Options Object', options);

    if (isServerError(options)) {
        showErrorAlert(options.errorMessage);
        return;
    }

    options = PublicKeyCredential.parseRequestOptionsFromJSON(options);

    console.log('Assertion options', options);

    Swal.fire({
        title: 'Logging In...',
        text: 'Tap your security key to login.',
        imageUrl: '/images/securitykey.min.svg',
        showCancelButton: true,
        showConfirmButton: false,
        focusConfirm: false,
        focusCancel: false
    });

    let credential;
    try {
        credential = await navigator.credentials.get({ publicKey: options });
    } catch (e) {
        console.error('get() failed', e);
        if (isUserCancellation(e)) {
            Swal.close();
        } else {
            showErrorAlert(e.message ? e.message : e, e);
        }
        return;
    }

    if (!credential) {
        Swal.close();
        return;
    }

    let result;
    try {
        result = await postJson('/makeAssertion', credential.toJSON());
    } catch (e) {
        showErrorAlert('Could not verify the assertion with the server.', e);
        return;
    }

    console.log('Assertion Object', result);

    if (isServerError(result)) {
        showErrorAlert(result.errorMessage);
        return;
    }

    await Swal.fire({
        title: 'Logged In!',
        text: 'You\'re logged in successfully.',
        icon: 'success',
        timer: 2000
    });
}

// ---------------------------------------------------------------------------------------------------
// WebAuthn L3 §5.1.10 -- signal methods
//
// The server produces the payload; the browser makes the call. They are best-effort and report nothing
// back, so a resolved promise means only that the payload was well formed.
// ---------------------------------------------------------------------------------------------------

/** Tell the authenticator a credential it offered is not one this Relying Party knows about. */
async function signalUnknownCredential(credentialId) {
    if (!PublicKeyCredential.signalUnknownCredential) {
        return 'This browser does not support signalUnknownCredential().';
    }

    const options = await postForm('/signal/unknownCredential', { credentialId });
    if (isServerError(options)) {
        return options.errorMessage;
    }

    await PublicKeyCredential.signalUnknownCredential(options);
    return 'Signalled that the credential is unknown.';
}

/**
 * Give the authenticator the complete set of credential IDs still accepted for a user.
 *
 * The list must be exhaustive: an authenticator may delete anything missing from it, so a Relying Party
 * that cannot enumerate every credential for the user should not call this at all.
 */
async function signalAllAcceptedCredentials(username) {
    if (!PublicKeyCredential.signalAllAcceptedCredentials) {
        return 'This browser does not support signalAllAcceptedCredentials().';
    }

    const options = await postForm('/signal/allAcceptedCredentials', { username });
    if (isServerError(options)) {
        return options.errorMessage;
    }

    await PublicKeyCredential.signalAllAcceptedCredentials(options);
    return 'Signalled ' + options.allAcceptedCredentialIds.length + ' accepted credential(s).';
}

/** Refresh the name and display name the authenticator shows for a user's credentials. */
async function signalCurrentUserDetails(username) {
    if (!PublicKeyCredential.signalCurrentUserDetails) {
        return 'This browser does not support signalCurrentUserDetails().';
    }

    const options = await postForm('/signal/currentUserDetails', { username });
    if (isServerError(options)) {
        return options.errorMessage;
    }

    await PublicKeyCredential.signalCurrentUserDetails(options);
    return 'Signalled current user details for ' + options.name + '.';
}

// ---------------------------------------------------------------------------------------------------
// WebAuthn L3 §5.1.7 -- client capabilities
// ---------------------------------------------------------------------------------------------------

/**
 * Asks the browser what it can do, so a page can offer only the ceremonies that will actually work.
 * Returns null on browsers that predate the method.
 */
async function getClientCapabilities() {
    if (!PublicKeyCredential.getClientCapabilities) {
        return null;
    }

    try {
        return await PublicKeyCredential.getClientCapabilities();
    } catch (e) {
        console.warn('getClientCapabilities() failed', e);
        return null;
    }
}

/**
 * Renders the capability report into an element, if the page has one.
 * Used by the custom page to show what the current browser supports.
 */
async function renderClientCapabilities(containerId) {
    const container = document.getElementById(containerId);
    if (!container) {
        return;
    }

    const capabilities = await getClientCapabilities();
    if (!capabilities) {
        container.innerHTML = '<p class="help">This browser does not support '
            + '<code>getClientCapabilities()</code> (WebAuthn Level 3 &sect;5.1.7).</p>';
        return;
    }

    const tags = Object.keys(capabilities).sort().map(function (name) {
        const supported = capabilities[name];
        return '<span class="tag ' + (supported ? 'is-success' : 'is-light') + '">'
            + name + ': ' + supported + '</span>';
    });

    container.innerHTML = '<div class="tags">' + tags.join('') + '</div>';
}
