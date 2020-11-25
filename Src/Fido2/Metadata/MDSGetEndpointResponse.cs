﻿using Newtonsoft.Json;

namespace Fido2NetLib
{
    internal class MDSGetEndpointResponse
    {
        [JsonProperty("status", Required = Required.Always)]
        public string Status { get; set; }
        [JsonProperty("result", Required = Required.Always)]
        public string[] Result { get; set; }
    }
}
