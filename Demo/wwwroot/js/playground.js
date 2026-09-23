// The playground page: every option this Relying Party can set, the request it produces, and the decoded
// result. The ceremonies themselves come from webauthn.js -- this file is wiring and rendering.

function show(id, text) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = text;
    }
}

function pretty(value) {
    return JSON.stringify(value, null, 2);
}

// --------------------------------------------------------------------------------------------------
// Tabs
// --------------------------------------------------------------------------------------------------

document.querySelectorAll('#playground-tabs li').forEach(function (tab) {
    tab.addEventListener('click', function () {
        document.querySelectorAll('#playground-tabs li').forEach(t => t.classList.remove('is-active'));
        tab.classList.add('is-active');
        document.querySelectorAll('.playground-panel').forEach(function (panel) {
            panel.style.display = panel.id === 'panel-' + tab.dataset.tab ? '' : 'none';
        });
        if (tab.dataset.tab === 'credentials') {
            loadCredentials();
        }
    });
});

// --------------------------------------------------------------------------------------------------
// Ceremony
// --------------------------------------------------------------------------------------------------

function currentOptions() {
    return {
        username: value('#pg-username'),
        displayName: value('#pg-displayname'),
        attestation: value('#option-attestation'),
        authenticatorAttachment: value('#option-authenticator'),
        userVerification: value('#option-userverification'),
        residentKey: value('#option-residentkey'),
        hints: checkedValues('.option-hint'),
        attestationFormats: checkedValues('.option-attestation-format'),
        algorithms: checkedValues('.option-algorithm'),
        prf: value('#option-prf'),
        mediation: value('#option-mediation'),

        // Keep the playground on the playground rather than redirecting to the dashboard.
        stayOnPage: true,

        onRequest: function (options) {
            show('pg-request-preview', pretty(options));
        },
        onResponse: async function (response) {
            show('pg-response-raw', pretty(response));
            await decodeCeremonyResponse(response);
        }
    };
}

document.getElementById('pg-register').addEventListener('click', async function () {
    show('pg-status', 'Registering...');
    await registerCeremony(currentOptions());
    show('pg-status', '');
    loadCredentials();
});

document.getElementById('pg-authenticate').addEventListener('click', async function () {
    show('pg-status', 'Authenticating...');
    await signInCeremony(currentOptions());
    show('pg-status', '');
    loadCredentials();
});

// --------------------------------------------------------------------------------------------------
// Response decoding
//
// The response tab reuses the same decoder endpoint the Decoder tab uses, so what you see here is what
// the library itself parsed -- not a second, parallel implementation that could drift from it.
// --------------------------------------------------------------------------------------------------

async function decodeCeremonyResponse(response) {
    const blob = response.response &&
        (response.response.attestationObject || response.response.authenticatorData);

    if (!blob) {
        return;
    }

    const decoded = await postJson('/api/playground/decode', { input: blob, kind: 'auto' });
    if (decoded.status !== 'ok') {
        show('pg-response-summary', '');
        return;
    }

    renderResponseSummary(decoded);
}

function flagTag(name, on, title) {
    return '<span class="tag pg-flag ' + (on ? 'is-success' : 'is-light') + '" title="' + title + '">'
        + name + ': ' + (on ? 'set' : 'clear') + '</span>';
}

function renderResponseSummary(decoded) {
    const authData = decoded.decoded.authData || decoded.decoded;
    if (!authData || !authData.flags) {
        show('pg-response-summary', '');
        return;
    }

    const f = authData.flags;
    let html = '<div class="tags">'
        + flagTag('UP', f.up, 'User Present')
        + flagTag('UV', f.uv, 'User Verified')
        + flagTag('BE', f.be, 'Backup Eligible')
        + flagTag('BS', f.bs, 'Backup State')
        + flagTag('AT', f.at, 'Attested credential data included')
        + flagTag('ED', f.ed, 'Extension data included')
        + '</div>';

    html += '<p><strong>Sign count:</strong> ' + authData.signCount + '</p>';

    if (decoded.decoded.fmt) {
        html += '<p><strong>Attestation format:</strong> <code>' + decoded.decoded.fmt + '</code></p>';
    }

    const acd = authData.attestedCredentialData;
    if (acd) {
        html += '<p><strong>AAGUID:</strong> <code>' + acd.aaguid + '</code>';
        if (acd.aaguidDescription) {
            html += ' &mdash; ' + acd.aaguidDescription + ' <span class="tag is-info is-light">FIDO MDS</span>';
        } else {
            html += ' <span class="tag is-light">not in metadata</span>';
        }
        html += '</p>';
        html += '<p><strong>Credential ID:</strong> <code>' + acd.credentialId + '</code> ('
            + acd.credentialIdLength + ' bytes)</p>';
    }

    document.getElementById('pg-response-summary').innerHTML = html;
}

// --------------------------------------------------------------------------------------------------
// Decoder tab
// --------------------------------------------------------------------------------------------------

document.getElementById('pg-decode').addEventListener('click', async function () {
    const input = value('#pg-decode-input');
    if (!input) {
        show('pg-decode-output', 'Paste something to decode.');
        return;
    }

    const result = await postJson('/api/playground/decode', {
        input: input,
        kind: value('#pg-decode-kind')
    });

    if (result.status !== 'ok') {
        show('pg-decode-output', 'Error: ' + result.errorMessage);
        return;
    }

    show('pg-decode-output', 'Detected: ' + result.kind + ' (' + result.byteLength + ' bytes)\n\n'
        + pretty(result.decoded));
});

// --------------------------------------------------------------------------------------------------
// Credentials tab
// --------------------------------------------------------------------------------------------------

function tri(value, trueLabel, falseLabel, unknownTitle) {
    if (value === true) return '<span class="tag is-success">' + trueLabel + '</span>';
    if (value === false) return '<span class="tag">' + falseLabel + '</span>';
    return '<span class="tag is-light" title="' + unknownTitle + '">unknown</span>';
}

async function loadCredentials() {
    const username = value('#pg-username');
    const container = document.getElementById('pg-credentials');
    if (!container || !username) {
        return;
    }

    const result = await fetch('/api/playground/credentials?username=' + encodeURIComponent(username))
        .then(r => r.json());

    if (result.status !== 'ok' || !result.credentials.length) {
        container.innerHTML = '<p class="help">No credentials registered for this user yet.</p>';
        return;
    }

    let html = '<div class="table-container"><table class="table is-striped is-fullwidth"><thead><tr>'
        + '<th>Nickname</th><th>Authenticator</th><th>Registered</th><th>Count</th><th>Attestation</th>'
        + '<th>Transports</th><th>Discoverable</th><th>uvInit</th><th>BE</th><th>BS</th><th></th>'
        + '</tr></thead><tbody>';

    result.credentials.forEach(function (c) {
        html += '<tr>'
            + '<td><input class="input is-small pg-nickname" data-id="' + c.id + '" value="'
                + (c.nickname || '') + '" placeholder="name this key" /></td>'
            + '<td>' + (c.authenticator || '<span class="has-text-grey">not in metadata</span>') + '</td>'
            + '<td>' + new Date(c.regDate).toISOString().slice(0, 16).replace('T', ' ') + '</td>'
            + '<td>' + c.signCount + '</td>'
            + '<td>' + c.attestationFormat + '</td>'
            + '<td>' + (c.transports.length ? c.transports.join(', ') : '<span class="has-text-grey">none</span>') + '</td>'
            + '<td>' + tri(c.isDiscoverable, 'yes', 'no', 'The client did not report credProps.rk') + '</td>'
            + '<td>' + tri(c.uvInitialized, 'yes', 'no', '') + '</td>'
            + '<td>' + tri(c.isBackupEligible, 'yes', 'no', '') + '</td>'
            + '<td>' + tri(c.isBackedUp, 'yes', 'no', '') + '</td>'
            + '<td><button class="button is-small is-danger is-light pg-delete" data-id="' + c.id + '">Delete</button></td>'
            + '</tr>';
    });

    container.innerHTML = html + '</tbody></table></div>';
    wireCredentialRowActions();
}

function wireCredentialRowActions() {
    document.querySelectorAll('.pg-nickname').forEach(function (input) {
        input.addEventListener('change', async function () {
            const body = new FormData();
            body.append('credentialId', input.dataset.id);
            body.append('nickname', input.value);
            await fetch('/api/playground/credentials/nickname', { method: 'POST', body });
            show('pg-credential-status', 'Nickname saved.');
        });
    });

    document.querySelectorAll('.pg-delete').forEach(function (button) {
        button.addEventListener('click', async function () {
            const body = new FormData();
            body.append('credentialId', button.dataset.id);
            const result = await fetch('/api/playground/credentials/delete', { method: 'POST', body })
                .then(r => r.json());

            if (result.status !== 'ok') {
                show('pg-credential-status', 'Delete failed: ' + result.errorMessage);
                return;
            }

            // Deleting server-side is only half the job: without a signal the authenticator keeps offering
            // the credential. §5.1.10 signalUnknownCredential is exactly this case.
            let message = 'Credential deleted.';
            try {
                message += ' ' + await signalUnknownCredential(button.dataset.id);
            } catch (e) {
                message += ' Signal failed: ' + (e.message ? e.message : e);
            }

            show('pg-credential-status', message);
            loadCredentials();
        });
    });
}

document.getElementById('pg-refresh-credentials').addEventListener('click', loadCredentials);

document.getElementById('pg-signal-all').addEventListener('click', async function () {
    try {
        show('pg-credential-status', await signalAllAcceptedCredentials(value('#pg-username')));
    } catch (e) {
        show('pg-credential-status', 'Signal failed: ' + (e.message ? e.message : e));
    }
});

document.getElementById('pg-signal-user').addEventListener('click', async function () {
    try {
        show('pg-credential-status', await signalCurrentUserDetails(value('#pg-username')));
    } catch (e) {
        show('pg-credential-status', 'Signal failed: ' + (e.message ? e.message : e));
    }
});

// --------------------------------------------------------------------------------------------------

renderClientCapabilities('client-capabilities');
