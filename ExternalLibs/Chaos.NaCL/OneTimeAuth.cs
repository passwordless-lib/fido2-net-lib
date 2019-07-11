using System;

namespace Chaos.NaCl
{
    public abstract class OneTimeAuth
    {
        private static readonly Poly1305 _poly1305 = new Poly1305();

        public abstract int KeySizeInBytes { get; }
        public abstract int SignatureSizeInBytes { get; }

        public abstract byte[] Sign(byte[] message, byte[] key);
        public abstract void Sign(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> key);
        public abstract bool Verify(byte[] signature, byte[] message, byte[] key);
        public abstract bool Verify(ArraySegment<byte> signature, ArraySegment<byte> message, ArraySegment<byte> key);

        public static OneTimeAuth Poly1305 { get { return _poly1305; } }
    }
}
