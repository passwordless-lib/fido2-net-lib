// Passwordless: the authenticator verifies the user (PIN, biometric), so no password is involved.
// The credential is still looked up by username, so it need not be discoverable.

document.getElementById('register').addEventListener('submit', function (event) {
    event.preventDefault();

    registerCeremony({
        username: this.username.value,
        displayName: this.displayName.value,
        attestation: 'none',
        authenticatorAttachment: '',
        userVerification: 'preferred',
        residentKey: 'discouraged',

        // WebAuthn L3 §5.8.8. A hint is advisory: it tells the browser what kind of authenticator to lead
        // with in its UI, without constraining what the user may actually use.
        hints: ['client-device']
    });
});
