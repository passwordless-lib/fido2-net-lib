using System.Collections.Generic;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    /// <summary>
    /// This descriptor contains description in alternative languages.
    /// </summary>
    /// <remarks>
    /// <see href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-metadata-statement-v2.0-id-20180227.html#alternativedescriptions-dictionary"/>
    /// </remarks>
    public class AlternativeDescriptions
    {
        /// <summary>
        /// Gets or sets alternative descriptions of the authenticator.
        /// <para>
        /// Contains IETF language codes as key (e.g. "ru-RU", "de", "fr-FR") and a localized description as value.
        /// </para>
        /// </summary>
        /// <remarks>
        /// Contains IETF language codes, defined by a primary language subtag, 
        /// followed by a region subtag based on a two-letter country code from [ISO3166] alpha-2 (usually written in upper case).
        /// <para>Each description SHALL NOT exceed a maximum length of 200 characters.</para>
        /// <para>Description values can contain any UTF-8 characters.</para>
        /// </remarks>
        [JsonProperty("alternativeDescriptions")]
        public Dictionary<string, string> IETFLanguageCodesMembers { get; set; }
    }
}
