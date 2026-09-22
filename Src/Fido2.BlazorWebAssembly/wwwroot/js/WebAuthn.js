// Browser side of Fido2.BlazorWebAssembly. Loaded by WebAuthn.cs as an ES module, so this file must
// ship in the package as a static web asset: it is maintained as plain JavaScript on purpose, since a
// build-time TypeScript compile emits after static web assets have been enumerated and the output
// never reaches the nupkg.

export function isWebAuthnPossible() {
    return !!window.PublicKeyCredential;
}

/** @param {ArrayBuffer} arrayBuffer */
function toBase64Url(arrayBuffer) {
    return btoa(String.fromCharCode(...new Uint8Array(arrayBuffer))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");
}

/** @param {string} value */
function fromBase64Url(value) {
    return Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
}

/** @param {string} base64String */
function base64StringToUrl(base64String) {
    return base64String.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");
}

/** @param {PublicKeyCredentialCreationOptions} options */
export async function createCreds(options) {
    if (typeof options.challenge === 'string')
        options.challenge = fromBase64Url(options.challenge);
    if (typeof options.user.id === 'string')
        options.user.id = fromBase64Url(options.user.id);
    if (options.rp.id === null)
        options.rp.id = undefined;
    for (let cred of options.excludeCredentials) {
        if (typeof cred.id === 'string')
            cred.id = fromBase64Url(cred.id);
    }
    const newCreds = /** @type {PublicKeyCredential} */ (await navigator.credentials.create({ publicKey: options }));
    const response = /** @type {AuthenticatorAttestationResponse} */ (newCreds.response);
    return {
        id: base64StringToUrl(newCreds.id),
        rawId: toBase64Url(newCreds.rawId),
        type: newCreds.type,
        clientExtensionResults: newCreds.getClientExtensionResults(),
        response: {
            attestationObject: toBase64Url(response.attestationObject),
            clientDataJSON: toBase64Url(response.clientDataJSON),
            transports: response.getTransports ? response.getTransports() : []
        }
    };
}

/** @param {PublicKeyCredentialRequestOptions} options */
export async function verify(options) {
    if (typeof options.challenge === 'string')
        options.challenge = fromBase64Url(options.challenge);
    if (options.allowCredentials) {
        for (let i = 0; i < options.allowCredentials.length; i++) {
            const id = options.allowCredentials[i].id;
            if (typeof id === 'string')
                options.allowCredentials[i].id = fromBase64Url(id);
        }
    }
    const creds = /** @type {PublicKeyCredential} */ (await navigator.credentials.get({ publicKey: options }));
    const response = /** @type {AuthenticatorAssertionResponse} */ (creds.response);
    return {
        id: creds.id,
        rawId: toBase64Url(creds.rawId),
        type: creds.type,
        clientExtensionResults: creds.getClientExtensionResults(),
        response: {
            authenticatorData: toBase64Url(response.authenticatorData),
            clientDataJSON: toBase64Url(response.clientDataJSON),
            userHandle: response.userHandle && response.userHandle.byteLength > 0 ? toBase64Url(response.userHandle) : undefined,
            signature: toBase64Url(response.signature)
        }
    };
}
