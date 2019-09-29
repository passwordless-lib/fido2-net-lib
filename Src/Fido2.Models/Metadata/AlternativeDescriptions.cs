using System.Collections.Generic;
using Newtonsoft.Json;

namespace Fido2NetLib
{
    public class AlternativeDescriptions
    {
        [JsonProperty("alternativeDescriptions")]
        public Dictionary<string, string> IETFLanguageCodesMembers { get; set; }
    }
}
