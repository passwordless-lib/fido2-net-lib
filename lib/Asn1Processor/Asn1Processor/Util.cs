using System;
using System.IO;

namespace LCLib.Asn1Processor
{
	/// <summary>
	/// Summary description for Util.
	/// </summary>
	public class Asn1Util
	{
        public static int BytePrecision(ulong value)
        {
            int i;
            for (i=sizeof(ulong); i>0; --i)
                if ((value >> (i-1)*8)!=0)
                    break;
            return i;
        }

        public static int DERLengthEncode(Stream xdata, ulong length)
        {
            var i=0;
            if (length <= 0x7f)
            {
                xdata.WriteByte((byte)length);
                i++;
            }
            else
            {
                xdata.WriteByte((byte)(BytePrecision(length) | 0x80));
                i++;
                for (var j=BytePrecision((ulong)length); j>0; --j)
                {
                    xdata.WriteByte((byte)(length >> (j-1)*8));
                    i++;
                }
            }
            return i;
        }

        public static long DerLengthDecode(Stream bt)
        {
            long length = 0;
            byte b;
            b = (byte) bt.ReadByte();
            if ((b & 0x80)==0)
            {
                length = b;
            }
            else
            {
                long lengthBytes = b & 0x7f;
                if (lengthBytes == 0)
                {
                    throw new Exception("Indefinite length.");
                }
                length = 0;
                while (lengthBytes-- > 0)
                {
                    if ((length >> (8*(sizeof(long)-1))) > 0)
                        throw new Exception("Length overflow.");
                    b = (byte) bt.ReadByte();
                    length = (length << 8) | b;
                }
            }
            return length;
        }

		private Asn1Util()
		{
		}

    }
}
