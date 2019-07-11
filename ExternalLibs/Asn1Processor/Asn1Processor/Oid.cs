//+-------------------------------------------------------------------------------+
//| Copyright (c) 2003 Liping Dai. All rights reserved.                           |
//| Web: www.lipingshare.com                                                      |
//| Email: lipingshare@yahoo.com                                                  |
//|                                                                               |
//| Copyright and Permission Details:                                             |
//| =================================                                             |
//| Permission is hereby granted, free of charge, to any person obtaining a copy  |
//| of this software and associated documentation files (the "Software"), to deal |
//| in the Software without restriction, including without limitation the rights  |
//| to use, copy, modify, merge, publish, distribute, and/or sell copies of the   |
//| Software, subject to the following conditions:                                |
//|                                                                               |
//| 1. Redistributions of source code must retain the above copyright notice, this|
//| list of conditions and the following disclaimer.                              |
//|                                                                               |
//| 2. Redistributions in binary form must reproduce the above copyright notice,  |
//| this list of conditions and the following disclaimer in the documentation     |
//| and/or other materials provided with the distribution.                        |
//|                                                                               |
//| THE SOFTWARE PRODUCT IS PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND,        |
//| EITHER EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED         |
//| WARRANTIES OF TITLE, NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR        |
//| A PARTICULAR PURPOSE.                                                         |
//+-------------------------------------------------------------------------------+

using System;
using System.IO;

namespace LipingShare.LCLib.Asn1Processor
{
    /// <summary>
    /// Summary description for OID.
    /// This class is used to encode and decode OID strings.
    /// </summary>
    public class Oid
    {
        /// <summary>
        /// Encode OID string to byte array.
        /// </summary>
        /// <param name="oidStr">source string.</param>
        /// <returns>encoded array.</returns>
        public byte[] Encode(string oidStr)
        {
            var ms = new MemoryStream();
            Encode(ms, oidStr);
            ms.Position = 0;
            var retval = new byte[ms.Length];
            ms.Read(retval, 0, retval.Length);
            ms.Close();
            return retval;
        }

        /// <summary>
        /// Decode OID byte array to OID string.
        /// </summary>
        /// <param name="data">source byte array.</param>
        /// <returns>result OID string.</returns>
        public string Decode(byte[] data)
        {
            var ms = new MemoryStream(data)
            {
                Position = 0
            };
            var retval = Decode(ms);
            ms.Close();
            return retval;
        }
        
        /// <summary>
        /// Encode OID string and put result into <see cref="Stream"/>
        /// </summary>
        /// <param name="bt">output stream.</param>
        /// <param name="oidStr">source OID string.</param>
        public virtual void Encode(Stream bt, string oidStr) //TODO
        {
            var oidList = oidStr.Split('.');
            if (oidList.Length < 2) throw new Exception("Invalid OID string.");
            var values = new ulong[oidList.Length];
            for (var i = 0; i<oidList.Length; i++)
            {
                values[i] = Convert.ToUInt64(oidList[i]);
            }
            bt.WriteByte((byte)(values[0] * 40 + values[1]));
            for (var i=2; i<values.Length; i++)
                EncodeValue(bt, values[i]);
        }

        /// <summary>
        /// Decode OID <see cref="Stream"/> and return OID string.
        /// </summary>
        /// <param name="bt">source stream.</param>
        /// <returns>result OID string.</returns>
        public virtual string Decode(Stream bt)
        {
            var retval = "";
            byte b;
            ulong v = 0;
            b = (byte) bt.ReadByte();
            retval += Convert.ToString(b/40);
            retval += "." + Convert.ToString(b%40);
            while (bt.Position < bt.Length)
            {
                try
                {
                    DecodeValue(bt, ref v);
                    retval += "." + v.ToString();
                }
                catch(Exception e)
                {
                    throw new Exception("Failed to decode OID value: " + e.Message);
                }
            }
            return retval;
        }

        /// <summary>
        /// Default constructor
        /// </summary>
        public Oid() 
        {
        }

        /// <summary>
        /// Encode single OID value.
        /// </summary>
        /// <param name="bt">output stream.</param>
        /// <param name="v">source value.</param>
        protected void EncodeValue(Stream bt, ulong v)
        {
            for (var i=(Asn1Util.BitPrecision(v)-1)/7; i > 0; i--)
            {
                bt.WriteByte((byte)(0x80 | ((v >> (i*7)) & 0x7f)));
            }
            bt.WriteByte((byte)(v & 0x7f));
        }

        /// <summary>
        /// Decode single OID value.
        /// </summary>
        /// <param name="bt">source stream.</param>
        /// <param name="v">output value</param>
        /// <returns>OID value bytes.</returns>
        protected int DecodeValue(Stream bt, ref ulong v)
        {
            byte b;
            var i=0;
            v = 0;
            while (true)
            {
                b = (byte) bt.ReadByte();
                i++;
                v <<= 7;
                v += (ulong) (b & 0x7f);
                if ((b & 0x80) == 0)
                    return i;
            }
        }

    }
}

