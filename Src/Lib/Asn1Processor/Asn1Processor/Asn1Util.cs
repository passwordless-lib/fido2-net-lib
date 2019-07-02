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
	/// Utility functions.
	/// </summary>
	public class Asn1Util
	{

        /// <summary>
        /// Check if the string is ASN.1 encoded hex string.
        /// </summary>
        /// <param name="dataStr">The string.</param>
        /// <returns>true:Yes, false:No.</returns>
        public static bool IsAsn1EncodedHexStr(string dataStr)
        {
            var retval = false;
            try
            {
                var data = HexStrToBytes(dataStr);
                if (data.Length > 0)
                {
                    var node = new Asn1Node();
                    retval = node.LoadData(data);
                }
            }
            catch
            {
                retval = false;
            }
            return retval;
        }

        /// <summary>
        /// Format a string to have certain line length and character group length.
        /// Sample result FormatString(xstr,32,2):
        /// <code>07 AE 0B E7 84 5A D4 6C 6A BD DF 8F 89 88 9E F1</code>
        /// </summary>
        /// <param name="inStr">source string.</param>
        /// <param name="lineLen">line length.</param>
        /// <param name="groupLen">group length.</param>
        /// <returns></returns>
        public static string FormatString(string inStr, int lineLen, int groupLen)
        {
            var tmpCh = new char[inStr.Length*2];
            int i, c = 0, linec = 0;
            var gc = 0;
            for (i=0; i<inStr.Length; i++)
            {
                tmpCh[c++] = inStr[i];
                gc++;
                linec++;
                if (gc >= groupLen && groupLen > 0)
                {
                    tmpCh[c++] = ' ';
                    gc = 0;
                }
                if (linec >= lineLen)
                {
                    tmpCh[c++] = '\r';
                    tmpCh[c++] = '\n';
                    linec = 0;
                }
            }
            var retval = new string(tmpCh);
            retval = retval.TrimEnd('\0');
            retval = retval.TrimEnd('\n');
            retval = retval.TrimEnd('\r');
            return retval;
        }

        /// <summary>
        /// Generate a string by duplicating <see cref="char"/> xch.
        /// </summary>
        /// <param name="len">duplicate times.</param>
        /// <param name="xch">the duplicated character.</param>
        /// <returns></returns>
        public static string GenStr(int len, char xch)
        {
            var ch = new char[len];
            for (var i = 0; i<len; i++)
            {
                ch[i] = xch;
            }
            return new string(ch);
        }

        /// <summary>
        /// Convert byte array to a <see cref="long"/> integer.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static long BytesToLong(byte[] bytes)
        {
            long tempInt = 0;
            for(var i=0; i<bytes.Length; i++)
            {
                tempInt = tempInt<<8 | bytes[i];
            }
            return tempInt;
        }

        /// <summary>
        /// Convert a ASCII byte array to string, also filter out the null characters.
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string BytesToString(byte[] bytes)
        {
            var retval = "";
            if (bytes == null || bytes.Length < 1) return retval;
            var cretval = new char[bytes.Length];
            for (int i=0, j=0; i<bytes.Length; i++)
            {
                if (bytes[i] != '\0')
                {
                    cretval[j++] = (char) bytes[i];
                }
            }
            retval = new string(cretval);
            retval = retval.TrimEnd('\0');
            return retval;
        }

        /// <summary>
        /// Convert ASCII string to byte array.
        /// </summary>
        /// <param name="msg"></param>
        /// <returns></returns>
        public static byte[] StringToBytes(string msg)
        {
            var retval = new byte[msg.Length];
            for (var i=0; i<msg.Length; i++)
            {
                retval[i] = (byte) msg[i];
            }
            return retval;
        }

		/// <summary>
		/// Compare source and target byte array.
		/// </summary>
		/// <param name="source"></param>
		/// <param name="target"></param>
		/// <returns></returns>
		public static bool IsEqual(byte[] source, byte[] target)
		{
			if (source == null) return false;
			if (target == null) return false;
			if (source.Length != target.Length) return false;
			for (var i=0; i<source.Length; i++)
			{
				if (source[i] != target[i]) return false;
			}
			return true;
		}

        /// <summary>
        /// Constant hex digits array.
        /// </summary>
        static char[] hexDigits = { '0', '1', '2', '3', '4', '5', '6', '7',
		                            '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

        /// <summary>
        /// Convert a byte array to hex string.
        /// </summary>
        /// <param name="bytes">source array.</param>
        /// <returns>hex string.</returns>
		public static string ToHexString(byte[] bytes) 
		{
			if (bytes == null) return "";
			var chars = new char[bytes.Length * 2];
			int b, i;
			for (i = 0; i < bytes.Length; i++) 
			{
				b = bytes[i];
				chars[i * 2] = hexDigits[b >> 4];
				chars[i * 2 + 1] = hexDigits[b & 0xF];
			}
			return new string(chars);
		}

        /// <summary>
        /// Check if the character is a valid hex digits.
        /// </summary>
        /// <param name="ch">source character.</param>
        /// <returns>true:Valid, false:Invalid.</returns>
        public static bool IsValidHexDigits(char ch)
        {
            var retval = false;
            for (var i=0; i<hexDigits.Length; i++)
            {
                if (hexDigits[i] == ch)
                {
                    retval = true;
                    break;
                }
            }
            return retval;
        }

        /// <summary>
        /// Get hex digits value.
        /// </summary>
        /// <param name="ch">source character.</param>
        /// <returns>hex digits value.</returns>
        public static byte GetHexDigitsVal(char ch)
        {
            byte retval = 0;
            for (var i=0; i<hexDigits.Length; i++)
            {
                if (hexDigits[i] == ch)
                {
                    retval = (byte) i;
                    break;
                }
            }
            return retval;
        }

        /// <summary>
        /// Convert hex string to byte array.
        /// </summary>
        /// <param name="hexStr">Source hex string.</param>
        /// <returns>return byte array.</returns>
        public static byte[] HexStrToBytes(string hexStr)
        {
            hexStr = hexStr.Replace(" ", "");
            hexStr = hexStr.Replace("\r", "");
            hexStr = hexStr.Replace("\n", "");
            hexStr = hexStr.ToUpper();
            if ((hexStr.Length%2) != 0) throw new Exception("Invalid Hex string: odd length.");
            int i;
            for (i=0; i<hexStr.Length; i++)
            {
                if (!IsValidHexDigits(hexStr[i]))
                {
                    throw new Exception("Invalid Hex string: included invalid character [" + 
                        hexStr[i] +"]");
                }
            }
            var bc = hexStr.Length/2;
            var retval = new byte[bc];
            int b1,b2, b;
            for (i=0; i<bc; i++)
            {
                b1 = GetHexDigitsVal(hexStr[i*2]);
                b2 = GetHexDigitsVal(hexStr[i*2+1]);
                b = ((b1 << 4) | b2);
                retval[i] = (byte) b;
            }
            return retval;
        }

        /// <summary>
        /// Check if the source string is a valid hex string.
        /// </summary>
        /// <param name="hexStr">source string.</param>
        /// <returns>true:Valid, false:Invalid.</returns>
        public static bool IsHexStr(string hexStr)
        {
            byte[] bytes = null;
            try
            {
                bytes = HexStrToBytes(hexStr);
            }
            catch
            {
                return false;
            }
            if (bytes == null || bytes.Length < 0)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        private const string PemStartStr = "-----BEGIN";
        private const string PemEndStr = "-----END";
        /// <summary>
        /// Check if the source string is PEM formated string.
        /// </summary>
        /// <param name="pemStr">source string.</param>
        /// <returns>true:Valid, false:Invalid.</returns>
        public static bool IsPemFormated(string pemStr)
        {
            byte[] data = null;
            try
            {
                data = PemToBytes(pemStr);
            }
            catch
            {
                return false;
            }
            return (data.Length > 0);
        }

        /// <summary>
        /// Check if a file is PEM formated.
        /// </summary>
        /// <param name="fileName">source file name.</param>
        /// <returns>true:Yes, false:No.</returns>
        public static bool IsPemFormatedFile(string fileName)
        {
            var retval = false;
            try
            {
                var fs = new FileStream(fileName, FileMode.Open);
                var data = new byte[fs.Length];
                fs.Read(data, 0, data.Length);
                fs.Close();
                var dataStr = BytesToString(data);
                retval = IsPemFormated(dataStr);
            }
            catch
            {
                retval = false;
            }
            return retval;
        }

        /// <summary>
        /// Convert PEM formated string into <see cref="Stream"/> and set the Stream position to 0.
        /// </summary>
        /// <param name="pemStr">source string.</param>
        /// <returns>output stream.</returns>
        public static Stream PemToStream(string pemStr)
        {
            var bytes = PemToBytes(pemStr);
            var retval = new MemoryStream(bytes);
            retval.Position = 0;
            return retval;
        }

        /// <summary>
        /// Convert PEM formated string into byte array.
        /// </summary>
        /// <param name="pemStr">source string.</param>
        /// <returns>output byte array.</returns>
        public static byte[] PemToBytes(string pemStr)
        {
            byte[] retval = null;
            var lines = pemStr.Split('\n');
            var base64Str = "";
            bool started = false, ended = false;
            var cline = "";
            for (var i = 0; i<lines.Length; i++)
            {
                cline = lines[i].ToUpper();
                if (cline == "") continue;
                if (cline.Length > PemStartStr.Length)
                {
                    if (!started && cline.Substring(0, PemStartStr.Length) == PemStartStr)
                    {
                        started = true;
                        continue;
                    }
                }
                if (cline.Length > PemEndStr.Length)
                {
                    if (cline.Substring(0, PemEndStr.Length) == PemEndStr)
                    {
                        ended = true;
                        break;
                    }
                }
                if (started)
                {
                    base64Str += lines[i];
                }
            }
            if (!(started && ended))
            {
                throw new Exception("'BEGIN'/'END' line is missing.");
            }
            base64Str = base64Str.Replace("\r", "");
            base64Str = base64Str.Replace("\n", "");
            base64Str = base64Str.Replace("\n", " ");
            retval = Convert.FromBase64String(base64Str);
            return retval;
        }

        /// <summary>
        /// Convert byte array to PEM formated string.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string BytesToPem(byte[] data)
        {
            return BytesToPem(data, "");
        }

        /// <summary>
        /// Retrieve PEM file heading.
        /// </summary>
        /// <param name="fileName">source file name.</param>
        /// <returns>heading string.</returns>
        public static string GetPemFileHeader(string fileName)
        {
            try
            {
                var fs = new FileStream(fileName, FileMode.Open);
                var data = new byte[fs.Length];
                fs.Read(data, 0, data.Length);
                fs.Close();
                var dataStr = BytesToString(data);
                return GetPemHeader(dataStr);
            }
            catch
            {
                return "";
            }
        }

        /// <summary>
        /// Retrieve PEM heading from a PEM formated string.
        /// </summary>
        /// <param name="pemStr">source string.</param>
        /// <returns>heading string.</returns>
        public static string GetPemHeader(string pemStr)
        {
            var lines = pemStr.Split('\n');
            var started = false;
            var cline = "";
            for (var i = 0; i<lines.Length; i++)
            {
                cline = lines[i].ToUpper().Replace("\r", "");
                if (cline == "") continue;
                if (cline.Length > PemStartStr.Length)
                {
                    if (!started && cline.Substring(0, PemStartStr.Length) == PemStartStr)
                    {
                        started = true;
                        var retstr = lines[i].Substring(PemStartStr.Length, 
                                lines[i].Length - 
                                PemStartStr.Length).Replace("-----","");
                        return retstr.Replace("\r", "");
                    }
                }
                else
                {
                    continue;
                }
            }
            return "";
        }

        /// <summary>
        /// Convert byte array to PEM formated string and set the heading as pemHeader.
        /// </summary>
        /// <param name="data">source array.</param>
        /// <param name="pemHeader">PEM heading.</param>
        /// <returns>PEM formated string.</returns>
        public static string BytesToPem(byte[] data, string pemHeader)
        {
            if (pemHeader == null || pemHeader.Length<1)
            {
                pemHeader = "ASN.1 Editor Generated PEM File";
            }
            var retval = "";
            if (pemHeader.Length > 0 && pemHeader[0] != ' ')
            {
                pemHeader = " " + pemHeader;
            }
            retval = Convert.ToBase64String(data);
            retval = FormatString(retval, 64, 0);
            retval = "-----BEGIN"+ pemHeader +"-----\r\n" +
                     retval +
                     "\r\n-----END"+ pemHeader +"-----\r\n";
            return retval;
        }

        /// <summary>
        /// Calculate how many bits is enough to hold ivalue.
        /// </summary>
        /// <param name="ivalue">source value.</param>
        /// <returns>bits number.</returns>
        public static int BitPrecision(ulong ivalue)
        {
	        if (ivalue == 0) return 0;
            int l = 0, h = 8 * 4; // 4: sizeof(ulong)
	        while (h-l > 1)
	        {
		        var t = (int) (l+h)/2;
		        if ((ivalue >> t) != 0)
			        l = t;
		        else
			        h = t;
	        }
	        return h;
        }

        /// <summary>
        /// Calculate how many bytes is enough to hold the value.
        /// </summary>
        /// <param name="value">input value.</param>
        /// <returns>bytes number.</returns>
        public static int BytePrecision(ulong value)
        {
            int i;
            for (i = 4; i > 0; --i) // 4: sizeof(ulong)
                 if ((value >> (i-1)*8)!=0)
                    break;
            return i;
        }

        /// <summary>
        /// ASN.1 DER length encoder.
        /// </summary>
        /// <param name="xdata">result output stream.</param>
        /// <param name="length">source length.</param>
        /// <returns>result bytes.</returns>
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

        /// <summary>
        /// ASN.1 DER length decoder.
        /// </summary>
        /// <param name="bt">Source stream.</param>
        /// <param name="isIndefiniteLength">Output parameter.</param>
        /// <returns>Output length.</returns>
        public static long DerLengthDecode(Stream bt, ref bool isIndefiniteLength)
        {
			isIndefiniteLength = false;
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
					isIndefiniteLength = true;
					var sPos = bt.Position;
                    return -2; // Indefinite length.
                }
                length = 0;
                while (lengthBytes-- > 0)
                {
                    if ((length >> (8 * (4 - 1))) > 0) // 4: sizeof(long)
                    {
                        return -1; // Length overflow.
                    }
                    b = (byte) bt.ReadByte();
                    length = (length << 8) | b;
                }
            }
            return length;
        }

        /// <summary>
        /// Decode tag value to return tag name.
        /// </summary>
        /// <param name="tag">input tag.</param>
        /// <returns>tag name.</returns>
        static public string GetTagName(byte tag)
        {
            var retval = "";
            if ((tag & Asn1TagClasses.CLASS_MASK) != 0)
            {
                switch (tag & Asn1TagClasses.CLASS_MASK)
                {
                    case Asn1TagClasses.CONTEXT_SPECIFIC:
                        retval += "CONTEXT SPECIFIC (" + ((int)(tag & Asn1Tag.TAG_MASK)).ToString() +")";
                        break;
                    case Asn1TagClasses.APPLICATION:
                        retval += "APPLICATION (" + ((int)(tag & Asn1Tag.TAG_MASK)).ToString() +")";
                        break;
                    case Asn1TagClasses.PRIVATE:
                        retval += "PRIVATE (" + ((int)(tag & Asn1Tag.TAG_MASK)).ToString() +")";
                        break;
                    case Asn1TagClasses.CONSTRUCTED:
                        retval += "CONSTRUCTED (" + ((int)(tag & Asn1Tag.TAG_MASK)).ToString() +")";
                        break;
					case Asn1TagClasses.UNIVERSAL:
						retval += "UNIVERSAL (" + ((int)(tag & Asn1Tag.TAG_MASK)).ToString() +")";
						break;
                }
            }
            else
            {
                switch (tag & Asn1Tag.TAG_MASK)
                {
                    case Asn1Tag.BOOLEAN:
                        retval += "BOOLEAN";
                        break;
                    case Asn1Tag.INTEGER:
                        retval += "INTEGER";
                        break;
                    case Asn1Tag.BIT_STRING:
                        retval += "BIT STRING";
                        break;
                    case Asn1Tag.OCTET_STRING:
                        retval += "OCTET STRING";
                        break;
                    case Asn1Tag.TAG_NULL:
                        retval += "NULL";
                        break;
                    case Asn1Tag.OBJECT_IDENTIFIER:
                        retval += "OBJECT IDENTIFIER";
                        break;
                    case Asn1Tag.OBJECT_DESCRIPTOR:
                        retval += "OBJECT DESCRIPTOR";
                        break;
                    case Asn1Tag.RELATIVE_OID:
                        retval += "RELATIVE-OID";
                        break;
                    case Asn1Tag.EXTERNAL:
                        retval += "EXTERNAL";
                        break;
                    case Asn1Tag.REAL:
                        retval += "REAL";
                        break;
                    case Asn1Tag.ENUMERATED:
                        retval += "ENUMERATED";
                        break;
                    case Asn1Tag.UTF8_STRING:
                        retval += "UTF8 STRING";
                        break;
                    case (Asn1Tag.SEQUENCE):
                        retval += "SEQUENCE";
                        break;
                    case (Asn1Tag.SET):
                        retval += "SET";
                        break;
                    case Asn1Tag.NUMERIC_STRING:
                        retval += "NUMERIC STRING";
                        break;
                    case Asn1Tag.PRINTABLE_STRING:
                        retval += "PRINTABLE STRING";
                        break;
                    case Asn1Tag.T61_STRING:
                        retval += "T61 STRING";
                        break;
                    case Asn1Tag.VIDEOTEXT_STRING:
                        retval += "VIDEOTEXT STRING";
                        break;
                    case Asn1Tag.IA5_STRING:
                        retval += "IA5 STRING";
                        break;
                    case Asn1Tag.UTC_TIME:
                        retval += "UTC TIME";
                        break;
                    case Asn1Tag.GENERALIZED_TIME:
                        retval += "GENERALIZED TIME";
                        break;
                    case Asn1Tag.GRAPHIC_STRING:
                        retval += "GRAPHIC STRING";
                        break;
                    case Asn1Tag.VISIBLE_STRING:
                        retval += "VISIBLE STRING";
                        break;
                    case Asn1Tag.GENERAL_STRING:
                        retval += "GENERAL STRING";
                        break;
                    case Asn1Tag.UNIVERSAL_STRING:
                        retval += "UNIVERSAL STRING";
                        break;
                    case Asn1Tag.BMPSTRING:
                        retval += "BMP STRING";
                        break;
                    default:
                        retval += "UNKNOWN TAG";
                        break;
                };
            }
            return retval;
        }

        /// <summary>
        /// Constructor.
        /// </summary>
		private Asn1Util()
		{
			//Private constructor.
		}

    }
}
