using Newtonsoft.Json;
using System;

namespace Fido2NetLib
{
    [JsonConverter(typeof(ToStringJsonConverter))]
    public class TypedString : IEquatable<TypedString>
    {

        [JsonConstructor]
        protected TypedString(string value)
        {
            Value = value;
        }

        public string Value { get; private set; }

        public static implicit operator string(TypedString op) { return op.Value; }

        public override string ToString()
        {
            return Value;
        }        

        public bool Equals(TypedString other)
        {
            if (ReferenceEquals(this, other))
                return true;

            if (ReferenceEquals(null, other))
                return false;

            //if your below implementation will involve objects of derived classes, then do a 
            //GetType == other.GetType comparison
            if (GetType() != other.GetType())
                return false;

            if (Value == other.Value)
                return true;

            return false;
        }

        public override bool Equals(object obj)
        {
            return Equals(obj as TypedString);
        }

        public static bool operator ==(TypedString e1, TypedString e2)
        {
            if (ReferenceEquals(e1, null))
                return ReferenceEquals(e2, null);

            return e1.Equals(e2);
        }

        public static bool operator !=(TypedString e1, TypedString e2)
        {
            return !(e1 == e2);
        }

        public override int GetHashCode()
        {
            return Value.GetHashCode();
            //throw new NotImplementedException("Your lightweight hashing algorithm, consistent with Equals method, here...");
        }
    }
}
