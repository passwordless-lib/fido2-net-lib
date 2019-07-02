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
	/// ASN.1 encoded data parser.
	/// This a higher level class which unilized Asn1Node class functionality to 
	/// provide functions for ASN.1 encoded files. 
	/// </summary>
	public class Asn1Parser
	{
        private Asn1Node rootNode = new Asn1Node();

		/// <summary>
		/// Get/Set parseEncapsulatedData. Reloading data is required after this property is reset.
		/// </summary>
		bool ParseEncapsulatedData 
		{ 
			get
			{
				return rootNode.ParseEncapsulatedData;
			}
			set
			{
				rootNode.ParseEncapsulatedData = value;
			}
		}

        /// <summary>
        /// Constructor.
        /// </summary>
		public Asn1Parser()
		{
		}

        /// <summary>
        /// Get raw ASN.1 encoded data.
        /// </summary>
		public byte[] RawData { get; private set; }

        /// <summary>
        /// Load ASN.1 encoded data from a file.
        /// </summary>
        /// <param name="fileName">File name.</param>
        public void LoadData(string fileName)
        {
            var fs = new FileStream(fileName, FileMode.Open);
            RawData = new byte[fs.Length];
            fs.Read(RawData, 0, (int)fs.Length);
            fs.Close();
            var ms = new MemoryStream(RawData);
            LoadData(ms);
        }

		/// <summary>
		/// Load PEM formated file.
		/// </summary>
		/// <param name="fileName">PEM file name.</param>
		public void LoadPemData(string fileName)
		{
			var fs = new FileStream(fileName, FileMode.Open);
			var data = new byte[fs.Length];
			fs.Read(data, 0, data.Length);
			fs.Close();
			var dataStr = Asn1Util.BytesToString(data);
			if (Asn1Util.IsPemFormated(dataStr))
			{
				var ms = Asn1Util.PemToStream(dataStr); 
				ms.Position = 0;
				LoadData(ms);
			}
			else
			{
				throw new Exception("It is a invalid PEM file: " + fileName);
			}
		}

        /// <summary>
        /// Load ASN.1 encoded data from Stream.
        /// </summary>
        /// <param name="stream">Stream data.</param>
        public void LoadData(Stream stream)
        {
            stream.Position = 0;
            if (!rootNode.LoadData(stream))
            {
                throw new Exception("Failed to load data.");
            }
            RawData = new byte[stream.Length];
            stream.Position = 0;
            stream.Read(RawData, 0, RawData.Length);
        }

        /// <summary>
        /// Save data into a file.
        /// </summary>
        /// <param name="fileName">File name.</param>
        public void SaveData(string fileName)
        {
            var fs = new FileStream(fileName, FileMode.Create);
            rootNode.SaveData(fs);
            fs.Close();
        }

        /// <summary>
        /// Get root node.
        /// </summary>
        public Asn1Node RootNode
        {
            get
            {
                return rootNode;
            }
        }

        /// <summary>
        /// Get a node by path string.
        /// </summary>
        /// <param name="nodePath">Path string.</param>
        /// <returns>Asn1Node or null.</returns>
        public Asn1Node GetNodeByPath(string nodePath)
        {
            return rootNode.GetDescendantNodeByPath(nodePath);
        }

		/// <summary>
		/// Get a node by OID.
		/// </summary>
		/// <param name="oid">OID string.</param>
		/// <returns>Asn1Node or null.</returns>
		public Asn1Node GetNodeByOid(string oid)
		{
			return Asn1Node.GetDecendantNodeByOid(oid, rootNode);
		}       

        /// <summary>
        /// Generate node text header. This method is used by GetNodeText to put heading.
        /// </summary>
        /// <param name="lineLen">Line length.</param>
        /// <returns>Header string.</returns>
        static public string GetNodeTextHeader(int lineLen)
        {
            var header = string.Format("Offset| Len  |LenByte|\r\n");
            header += "======+======+=======+" + Asn1Util.GenStr(lineLen+10, '=') + "\r\n";
            return header;
        }

        /// <summary>
        /// Generate the root node text description.
        /// </summary>
        /// <returns>Text string.</returns>
        public override string ToString()
        {
            return GetNodeText(rootNode, 100);
        }

        /// <summary>
        /// Generate node text description. It uses GetNodeTextHeader to generate
        /// the heading and Asn1Node.GetText to generate the node text.
        /// </summary>
        /// <param name="node">Target node.</param>
        /// <param name="lineLen">Line length.</param>
        /// <returns>Text string.</returns>
        public static string GetNodeText(Asn1Node node, int lineLen)
        {
            var nodeStr = GetNodeTextHeader(lineLen);
            nodeStr +=node.GetText(node, lineLen);
            return nodeStr;
        }

	}
}


