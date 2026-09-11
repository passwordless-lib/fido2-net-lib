// Custom: every option comes from the controls in _options.cshtml, so this page is the one to use when
// checking how a particular combination behaves in a particular browser.

document.getElementById('register').addEventListener('submit', function (event) {
    event.preventDefault();

    registerCeremony({
        username: this.username.value,
        displayName: this.displayName.value,
        attestation: value('#option-attestation'),
        authenticatorAttachment: value('#option-authenticator'),
        userVerification: value('#option-userverification'),
        residentKey: value('#option-residentkey'),

        // WebAuthn L3 §5.8.8 hints and §5.4 attestationFormats: both are ordered by preference and both
        // are advisory.
        hints: checkedValues('.option-hint'),
        attestationFormats: checkedValues('.option-attestation-format'),

        // WebAuthn L3 §10.1.4
        prf: value('#option-prf'),

        // WebAuthn L3 §5.1.3: a conditional create is offered without a modal prompt.
        mediation: value('#option-mediation')
    });
});

// WebAuthn L3 §5.1.7: report what this browser says it can do.
renderClientCapabilities('client-capabilities');
