// HELPERS

function showErrorAlert(message, error) {
    let footermsg = '';
    if (error) {
        footermsg = 'exception: ' + error.toString();
    }
    Swal.fire({
        // sweetalert2 renamed "type" to "icon" in v8; the old name is silently ignored, which is why these
        // alerts used to render without an icon.
        icon: 'error',
        title: 'Error',
        text: message,
        footer: footermsg
    });
}

/**
 * Shows the "browser does not support WebAuthn" banner when the API is missing.
 * Called on load by every scenario page.
 */
function detectFIDOSupport() {
    if (window.PublicKeyCredential === undefined ||
        typeof window.PublicKeyCredential !== "function") {
        const el = document.getElementById("notSupportedWarning");
        if (el) {
            el.style.display = 'block';
        }
    }
}

/**
 * Get a form value.
 * @param {string} selector
 */
function value(selector) {
    const el = document.querySelector(selector);
    if (!el) {
        return '';
    }
    if (el.type === "checkbox") {
        return el.checked;
    }
    return el.value;
}

/**
 * Collects the values of every checked checkbox matching a selector, in document order.
 * Used for the WebAuthn Level 3 members that take a list ordered by preference -- hints and
 * attestationFormats -- where the order of the controls on the page is the order of preference.
 * @param {string} selector
 */
function checkedValues(selector) {
    return Array.from(document.querySelectorAll(selector))
        .filter(el => el.checked)
        .map(el => el.value);
}

document.addEventListener('DOMContentLoaded', detectFIDOSupport);
