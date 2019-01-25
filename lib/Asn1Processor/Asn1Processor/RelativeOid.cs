using System;
using System.IO;

namespace LipingShare.LCLib.Asn1Processor
{
	/// <summary>
	/// Summary description for RelativeOid.
	/// </summary>
	public class RelativeOid : Oid
	{
        /// <summary>
        /// Constructor.
        /// </summary>
		public RelativeOid()
		{
		}

        /// <summary>
        /// Encode relative OID string and put result into <see cref="Stream"/>
        /// </summary>
        /// <param name="bt">output stream.</param>
        /// <param name="oidStr">source OID string.</param>
        public override void Encode(Stream bt, string oidStr)
        {
            var oidList = oidStr.Split('.');
            var values = new ulong[oidList.Length];
            for (var i = 0; i<oidList.Length; i++)
            {
                values[i] = Convert.ToUInt64(oidList[i]);
            }
            for (var i=0; i<values.Length; i++)
                EncodeValue(bt, values[i]);
        }

        /// <summary>
        /// Decode relative OID <see cref="Stream"/> and return OID string.
        /// </summary>
        /// <param name="bt">source stream.</param>
        /// <returns>result OID string.</returns>
        public override string Decode(Stream bt)
        {
            var retval = "";
            ulong v = 0;
            var isFirst = true;
            while (bt.Position < bt.Length)
            {
                try
                {
                    DecodeValue(bt, ref v);
                    if (isFirst)
                    {
                        retval = v.ToString();
                        isFirst = false;
                    }
                    else
                    {
                        retval += "." + v.ToString();
                    }
                }
                catch(Exception e)
                {
                    throw new Exception("Failed to decode OID value: " + e.Message);
                }
            }
            return retval;
        }
	}
}
