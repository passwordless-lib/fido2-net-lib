// Signal method buttons on the dashboard. See webauthn.js for what each call means.

function wireSignalButton(id, handler) {
    const button = document.getElementById(id);
    if (!button) {
        return;
    }

    button.addEventListener('click', async function () {
        const status = document.getElementById('signal-status');
        button.classList.add('is-loading');
        try {
            const message = await handler(button.dataset.username);
            status.textContent = message;
        } catch (e) {
            console.error(e);
            status.textContent = 'Signal failed: ' + (e.message ? e.message : e);
        } finally {
            button.classList.remove('is-loading');
        }
    });
}

wireSignalButton('signal-all-accepted', signalAllAcceptedCredentials);
wireSignalButton('signal-current-user', signalCurrentUserDetails);
