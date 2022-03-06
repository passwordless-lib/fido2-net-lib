﻿using System;
using System.Runtime.Serialization;

namespace Fido2NetLib
{
    /// <summary>
    /// Exception thrown when a new attestation comes from an authenticator with a current reported security issue.
    /// </summary>
    [Serializable]
    public class UndesiredMetdatataStatusFido2VerificationException : Fido2VerificationException
    {
        public UndesiredMetdatataStatusFido2VerificationException(StatusReport statusReport) : base($"Authenticator found with undesirable status. Was {statusReport.Status}")
        {
            StatusReport = statusReport;
        }

        protected UndesiredMetdatataStatusFido2VerificationException(SerializationInfo info, StreamingContext context) : base(info, context) { }

        /// <summary>
        /// Status report from the authenticator that caused the attestation to be rejected.
        /// </summary>
        public StatusReport StatusReport { get; }
    }
}
