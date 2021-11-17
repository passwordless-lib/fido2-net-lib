namespace Fido2NetLib
{
    internal static class AuthenticatorStatusExtensions
    {
        public static bool IsUndesired(this AuthenticatorStatus status)
        {
            return status
                is AuthenticatorStatus.ATTESTATION_KEY_COMPROMISE
                or AuthenticatorStatus.USER_VERIFICATION_BYPASS
                or AuthenticatorStatus.USER_KEY_REMOTE_COMPROMISE
                or AuthenticatorStatus.USER_KEY_PHYSICAL_COMPROMISE
                or AuthenticatorStatus.REVOKED;
        }
    }
}
