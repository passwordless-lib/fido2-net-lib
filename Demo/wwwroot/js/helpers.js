// HELPERS

function showErrorAlert(message, error) {
    let footermsg = '';
    if (error) {
        footermsg = 'exception:' + error.toString();
    }
    Swal.fire({
        type: 'error',
        title: 'Error',
        text: message,
        footer: footermsg
        //footer: '<a href>Why do I have this issue?</a>'
    })
}

function detectFIDOSupport() {
    if (window.PublicKeyCredential === undefined ||
        typeof window.PublicKeyCredential !== "function") {
        //$('#register-button').attr("disabled", true);
        //$('#login-button').attr("disabled", true);
        var el = document.getElementById("notSupportedWarning");
        if (el) {
            el.style.display = 'block';
        }
        return;
    }
}

/**
 * 
 * Get a form value
 * @param {any} selector
 */
function value(selector) {
    var el = document.querySelector(selector);
    if (el.type === "checkbox") {
        return el.checked;
    }
    return el.value;
}