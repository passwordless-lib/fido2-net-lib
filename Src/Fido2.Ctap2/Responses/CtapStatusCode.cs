namespace Fido2NetLib.Ctap2;

#pragma warning disable format
public enum CtapStatusCode
{
    OK                              = 0x00, // Indicates successful response
    CTAP1_ERR_INVALID_COMMAND       = 0x01, // The command is not a valid CTAP command
    CTAP1_ERR_INVALID_PARAMETER     = 0x02, // The command included an invalid parameter
    CTAP1_ERR_INVALID_LENGTH        = 0x03, // Invalid message or item length
    CTAP1_ERR_INVALID_SEQ           = 0x04, // Invalid message sequencing
    CTAP1_ERR_TIMEOUT               = 0x05, // Message timed out
    CTAP1_ERR_CHANNEL_BUSY          = 0x06, // Channel busy
    CTAP1_ERR_LOCK_REQUIRED         = 0x0A, // Command requires channel lock
    CTAP1_ERR_INVALID_CHANNEL       = 0x0B, // Command not allowed on this cid
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE  = 0x11, // Invalid/unexpected CBOR error
    CTAP2_ERR_INVALID_CBOR          = 0x12, // Error when parsing CBOR
    CTAP2_ERR_MISSING_PARAMETER     = 0x14, // Missing non-optional parameter
    CTAP2_ERR_LIMIT_EXCEEDED        = 0x15, // Limit for number of items exceeded
    CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16, // Unsupported extension
    CTAP2_ERR_CREDENTIAL_EXCLUDED   = 0x19, // Valid credential found in the exclude list
    CTAP2_ERR_PROCESSING            = 0x21, // Processing (Lengthy operation is in progress)
    CTAP2_ERR_INVALID_CREDENTIA     = 0x22, // Credential not valid for the authenticator
    CTAP2_ERR_USER_ACTION_PENDING   = 0x23, // Authentication is waiting for user interaction
    CTAP2_ERR_OPERATION_PENDING     = 0x24, // Processing, lengthy operation is in progress
    CTAP2_ERR_NO_OPERATIONS         = 0x25, // No request is pending
    CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26, // Authenticator does not support requested algorithm
    CTAP2_ERR_OPERATION_DENIED      = 0x27, // Not authorized for requested operation
    CTAP2_ERR_KEY_STORE_FULL        = 0x28, // Internal key storage is full
    CTAP2_ERR_NO_OPERATION_PENDING  = 0x2A, // No outstanding operations
    CTAP2_ERR_UNSUPPORTED_OPTION    = 0x2B, // Unsupported option
    CTAP2_ERR_INVALID_OPTION        = 0x2C, // Not a valid option for current operation
    CTAP2_ERR_KEEPALIVE_CANCEL      = 0x2D, // Pending keep alive was cancelled
    CTAP2_ERR_NO_CREDENTIALS        = 0x2E, // No valid credentials provided
    CTAP2_ERR_USER_ACTION_TIMEOUT   = 0x2F, // Timeout waiting for user interaction
    CTAP2_ERR_NOT_ALLOWED           = 0x30, // Continuation command, such as, authenticatorGetNextAssertion not allowed
    CTAP2_ERR_PIN_INVALID           = 0x31, // PIN Invalid
    CTAP2_ERR_PIN_BLOCKED           = 0x32, // PIN Blocked
    CTAP2_ERR_PIN_AUTH_INVALID      = 0x33, // PIN authentication,pinAuth, verification failed
    CTAP2_ERR_PIN_AUTH_BLOCKED      = 0x34, // PIN authentication,pinAuth, blocked. Requires power recycle to reset
    CTAP2_ERR_PIN_NOT_SET           = 0x35, // No PIN has been set
    CTAP2_ERR_PIN_REQUIRED          = 0x36, // PIN is required for the selected operation
    CTAP2_ERR_PIN_POLICY_VIOLATION  = 0x37, // PIN policy violation. Currently only enforces minimum length
    CTAP2_ERR_PIN_TOKEN_EXPIRED     = 0x38, // pinToken expired on authenticator
    CTAP2_ERR_REQUEST_TOO_LARGE     = 0x39, // Authenticator cannot handle this request due to memory constraints
    CTAP2_ERR_ACTION_TIMEOUT        = 0x3A, // The current operation has timed out
    CTAP2_ERR_UP_REQUIRED           = 0x3B, // User presence is required for the requested operation
    CTAP1_ERR_OTHER                 = 0x7F, // Other unspecified error
    CTAP2_ERR_SPEC_LAST             = 0xDF, // CTAP 2 spec last error
    CTAP2_ERR_EXTENSION_FIRST       = 0xE0, // Extension specific error
    CTAP2_ERR_EXTENSION_LAST        = 0xEF, // Extension specific error
    CTAP2_ERR_VENDOR_FIRST          = 0xF0, // Vendor specific error
    CTAP2_ERR_VENDOR_LAST           = 0xFF, // Vendor specific error
}
