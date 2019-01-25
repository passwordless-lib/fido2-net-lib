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

namespace LipingShare.LCLib.Asn1Processor
{
	/// <summary>
	/// BinaryView class. It is used to calculate hex view parameters.
	/// </summary>
	public class BinaryView
	{

        /// <summary>
        /// Default constructor.
        /// </summary>
        public BinaryView()
        {
            CalculatePar();
        }

        /// <summary>
        /// Set hex view parameters. It calls <see cref="CalculatePar"/> to get the parameters.
        /// <code>
        /// Parameters Definition:
        /// 000000  30 82 05 32 30 82 04 1A  A0 03 02 01 02 02 0A 1F  0..20...........
        /// 000010  CE 8F 20 00 00 00 00 00  22 30 0D 06 09 2A 86 48  .. ....."0...*.H
        /// |----|offsetWidth                                         |--dataWidth --|
        /// |----- hexWidth ---------------------------------------|
        /// |----- totalWidth -------------------------------------------------------|
        /// </code>
        /// </summary>
        /// <param name="offsetWidth">input</param>
        /// <param name="dataWidth">input</param>
        public void SetPar(int offsetWidth, int dataWidth)
        {
            OffsetWidth = offsetWidth;
            DataWidth = dataWidth;
            CalculatePar();
        }

        /// <summary>
        /// Constructor, it calls <see cref="SetPar"/> to set the parameters.
        /// </summary>
        /// <param name="offsetWidth">input</param>
        /// <param name="dataWidth">input</param>
		public BinaryView(int offsetWidth, int dataWidth)
		{
            SetPar(offsetWidth, dataWidth);
		}

        /// <summary>
        /// Get offsetWidth.
        /// </summary>
        public int OffsetWidth { get; private set; } = 6;

        /// <summary>
        /// Get dataWidth.
        /// </summary>
        public int DataWidth { get; private set; } = 16;

        /// <summary>
        /// Get totalWidth.
        /// </summary>
        public int TotalWidth { get; private set; }

        /// <summary>
        /// Get hexWidth.
        /// </summary>
        public int HexWidth { get; private set; }

        /// <summary>
        /// Calculate hex view parameters.
        /// </summary>
        protected void CalculatePar()
        {
            TotalWidth = OffsetWidth + 2 + DataWidth*3 + ((DataWidth/8) - 1) + 1 + DataWidth;
            HexWidth = TotalWidth - DataWidth;
        }

        /// <summary>
        /// Generate hex view text string by calling <see cref="GetBinaryViewText"/>.
        /// </summary>
        /// <param name="data">source byte array.</param>
        /// <returns>output string.</returns>
        public string GenerateText(byte[] data)
        {
            return GetBinaryViewText(data, OffsetWidth, DataWidth);
        }

        /// <summary>
        /// Calculate the byte <see cref="ByteLocation"/> by offset.
        /// </summary>
        /// <param name="byteOffset"></param>
        /// <param name="loc"></param>
        public void GetLocation(int byteOffset, ByteLocation loc)
        {
            var colOff = byteOffset - byteOffset/DataWidth * DataWidth;
            var line = byteOffset/DataWidth;
            var col = OffsetWidth + 2 + colOff * 3;
            var colLen = 3;
            var totOff = line * TotalWidth + line + col;
            var col2 = HexWidth + colOff;
            var totOff2 = line * TotalWidth + line + col2;
            var colLen2 = 1;
            loc.hexOffset = totOff;
            loc.hexColLen = colLen;
            loc.line = line;
            loc.chOffset = totOff2;
            loc.chColLen = colLen2;
        }

        /// <summary>
        /// Generate "Detail" hex view text.
        /// </summary>
        /// <param name="data">source byte array.</param>
        /// <param name="offsetWidth">offset text width.</param>
        /// <param name="dataWidth">data text width</param>
        /// <returns>detail hex view string.</returns>
        public static string GetBinaryViewText(byte[] data, int offsetWidth, int dataWidth)
        {
            var retval = "";
            var offForm = "{0:X"+offsetWidth+"}  ";
            int i, lineStart, lineEnd;
            int line = 0, offset = 0;
            var totalWidth = offsetWidth + 2 + dataWidth*3 + ((dataWidth/8) - 1) + 1 + dataWidth;
            var hexWidth = totalWidth - dataWidth;
            var dumpStr = "";
            var lineStr = "";
            for (offset = 0; offset<data.Length;)
            {
                lineStr = string.Format(offForm, (line++)*dataWidth);
                lineStart = offset;
                for (i=0; i<dataWidth; i++)
                {
                    lineStr += string.Format("{0:X2} ",data[offset++]);
                    if (offset>=data.Length) break;
                    if ((i+1)%8==0 && i!=0 && (i+1)<dataWidth) lineStr += " ";
                }
                lineStr += " ";
                lineEnd = offset;
                lineStr = lineStr.PadRight(hexWidth, ' ');
                for (i=lineStart; i<lineEnd; i++)
                {
                    if (data[i]<32 || data[i]>128)
                        lineStr += '.';
                    else
                        lineStr += (char)data[i];
                }
                lineStr = lineStr.PadRight(totalWidth, ' ');
                dumpStr += lineStr + "\r\n";
            }
            retval = dumpStr;
            return retval;
        }

	}

    /// <summary>
    /// ByteLocation class is used by <see cref="BinaryView"/> to transfer 
    /// location parameters.
    /// </summary>
    public class ByteLocation
    {
        /// <summary>
        /// line number.
        /// </summary>
        public int line = 0;

        /// <summary>
        /// Hex encoded data length.
        /// </summary>
        public int hexColLen = 3;

        /// <summary>
        /// Hex encoded data offset.
        /// </summary>
        public int hexOffset = 0;

        /// <summary>
        /// Character length.
        /// </summary>
        public int chColLen = 1;

        /// <summary>
        /// Character offset.
        /// </summary>
        public int chOffset = 0;

        /// <summary>
        /// Constructor.
        /// </summary>
        public ByteLocation()
        {
        }
    }
}
