// FIDO2 as a second factor: a normal password login is assumed to have happened already, so the
// credential does not need to be discoverable and user verification is only preferred.
// The ceremony itself lives in webauthn.js.

document.getElementById('register').addEventListener('submit', function (event) {
    event.preventDefault();

    registerCeremony({
        username: this.username.value,
        displayName: this.displayName.value,
        attestation: 'none',
        authenticatorAttachment: '',
        userVerification: 'preferred',
        residentKey: 'discouraged'
    });
});
