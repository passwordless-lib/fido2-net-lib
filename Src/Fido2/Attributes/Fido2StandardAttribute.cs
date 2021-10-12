using System;

namespace Fido2NetLib
{
    [AttributeUsage(AttributeTargets.All, AllowMultiple = false)]
    internal sealed class Fido2StandardAttribute : Attribute
    {
        public bool Optional { get; set; }
    }
}
