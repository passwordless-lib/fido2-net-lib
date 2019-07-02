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
using System.Collections;
using System.Text;

namespace LipingShare.LCLib.Asn1Processor
{
    /// <summary>
    /// IAsn1Node interface.
    /// </summary>
    public interface IAsn1Node
    {
        /// <summary>
        /// Load data from Stream.
        /// </summary>
        /// <param name="xdata"></param>
        /// <returns>true:Succeed; false:failed.</returns>
        bool LoadData(Stream xdata);

        /// <summary>
        /// Save node data into Stream.
        /// </summary>
        /// <param name="xdata">Stream.</param>
        /// <returns>true:Succeed; false:failed.</returns>
        bool SaveData(Stream xdata);
        
        /// <summary>
        /// Get parent node.
        /// </summary>
        Asn1Node ParentNode { get; }

        /// <summary>
        /// Add child node at the end of children list.
        /// </summary>
        /// <param name="xdata">Asn1Node</param>
        void AddChild(Asn1Node xdata);

        /// <summary>
        /// Insert a node in the children list before the pointed index.
        /// </summary>
        /// <param name="xdata">Asn1Node</param>
        /// <param name="index">0 based index.</param>
        int InsertChild(Asn1Node xdata, int index);

        /// <summary>
        /// Insert a node in the children list before the pointed node.
        /// </summary>
        /// <param name="xdata">Asn1Node that will be instered in the children list.</param>
        /// <param name="indexNode">Index node.</param>
		/// <returns>New node index.</returns>
		int InsertChild(Asn1Node xdata, Asn1Node indexNode);

        /// <summary>
        /// Insert a node in the children list after the pointed index.
        /// </summary>
        /// <param name="xdata">Asn1Node</param>
        /// <param name="index">0 based index.</param>
		/// <returns>New node index.</returns>
		int InsertChildAfter(Asn1Node xdata, int index);

        /// <summary>
        /// Insert a node in the children list after the pointed node.
        /// </summary>
        /// <param name="xdata">Asn1Node that will be instered in the children list.</param>
        /// <param name="indexNode">Index node.</param>
		/// <returns>New node index.</returns>
		int InsertChildAfter(Asn1Node xdata, Asn1Node indexNode);

        /// <summary>
        /// Remove a child from children node list by index.
        /// </summary>
        /// <param name="index">0 based index.</param>
        /// <returns>The Asn1Node just removed from the list.</returns>
        Asn1Node RemoveChild(int index);

        /// <summary>
        /// Remove the child from children node list.
        /// </summary>
        /// <param name="node">The node needs to be removed.</param>
        /// <returns></returns>
        Asn1Node RemoveChild(Asn1Node node);

        /// <summary>
        /// Get child node count.
        /// </summary>
        long ChildNodeCount { get; }

        /// <summary>
        /// Retrieve child node by index.
        /// </summary>
        /// <param name="index">0 based index.</param>
        /// <returns>0 based index.</returns>
        Asn1Node GetChildNode(int index);

        /// <summary>
        /// Get descendant node by node path.
        /// </summary>
        /// <param name="nodePath">relative node path that refer to current node.</param>
        /// <returns></returns>
        Asn1Node GetDescendantNodeByPath(string nodePath);

        /// <summary>
        /// Get/Set tag value.
        /// </summary>
        byte Tag{ get; set; }

        /// <summary>
        /// Get tag name.
        /// </summary>
        string TagName{ get; }

        /// <summary>
        /// Get data length. Not included the unused bits byte for BITSTRING.
        /// </summary>
        long DataLength{ get; }

        /// <summary>
        /// Get the length field bytes.
        /// </summary>
        long LengthFieldBytes{ get; }

        /// <summary>
        /// Get data offset.
        /// </summary>
        long DataOffset{ get; }

        /// <summary>
        /// Get unused bits for BITSTRING.
        /// </summary>
        byte UnusedBits{ get; }

        /// <summary>
        /// Get/Set node data by byte[], the data length field content and all the 
        /// node in the parent chain will be adjusted.
        /// </summary>
        byte[] Data { get; set; }

		/// <summary>
		/// Get/Set parseEncapsulatedData. This property will be inherited by the 
		/// child nodes when loading data.
		/// </summary>
		bool ParseEncapsulatedData { get; set; }

        /// <summary>
        /// Get the deepness of the node.
        /// </summary>
        long Deepness { get; }

        /// <summary>
        /// Get the path string of the node.
        /// </summary>
        string Path{ get; }

        /// <summary>
        /// Get the node and all the descendents text description.
        /// </summary>
        /// <param name="startNode">starting node.</param>
        /// <param name="lineLen">line length.</param>
        /// <returns></returns>
        string GetText(Asn1Node startNode, int lineLen);

        /// <summary>
        /// Retrieve the node description.
        /// </summary>
        /// <param name="pureHexMode">true:Return hex string only;
        /// false:Convert to more readable string depending on the node tag.</param>
        /// <returns>string</returns>
        string GetDataStr(bool pureHexMode);

        /// <summary>
        /// Get node label string.
        /// </summary>
        /// <param name="mask">
		/// <code>
		/// SHOW_OFFSET
		/// SHOW_DATA
		/// USE_HEX_OFFSET
		/// SHOW_TAG_NUMBER
		/// SHOW_PATH</code>
		/// </param>
        /// <returns>string</returns>
        string GetLabel(uint mask);

        /// <summary>
        /// Clone a new Asn1Node by current node.
        /// </summary>
        /// <returns>new node.</returns>
        Asn1Node Clone();

        /// <summary>
        /// Clear data and children list.
        /// </summary>
        void ClearAll();
    }

    /// <summary>
    /// Asn1Node, implemented IAsn1Node interface.
    /// </summary>
	public class Asn1Node : IAsn1Node
	{
        private long lengthFieldBytes;
		private byte[] data;
		private ArrayList childNodeList;
        private const int indentStep = 3;
        private bool isIndefiniteLength = false;
		private bool parseEncapsulatedData = true;

        /// <summary>
        /// Default Asn1Node text line length.
        /// </summary>
        public const int defaultLineLen = 80;

        /// <summary>
        /// Minium line length.
        /// </summary>
        public const int minLineLen = 60;

		private Asn1Node(Asn1Node parentNode, long dataOffset)
		{
			Init();
			Deepness = parentNode.Deepness + 1;
			this.ParentNode = parentNode;
			this.DataOffset = dataOffset;
		}

		private void Init()
		{
			childNodeList = new ArrayList();
			data = null;
			DataLength = 0;
			lengthFieldBytes = 0;
			UnusedBits = 0;
			Tag = Asn1Tag.SEQUENCE | Asn1TagClasses.CONSTRUCTED;
			childNodeList.Clear();
			Deepness = 0;
			ParentNode = null;
		}

		private string GetHexPrintingStr(Asn1Node startNode, string baseLine, 
			string lStr, int lineLen)
		{
			var nodeStr = "";
			var iStr = GetIndentStr(startNode);
			var dataStr = Asn1Util.ToHexString(data);
			if (dataStr.Length > 0)
			{
				if (baseLine.Length + dataStr.Length < lineLen)
				{
					nodeStr += baseLine + "'" + dataStr + "'";
				}
				else
				{
					nodeStr += baseLine + FormatLineHexString(
						lStr, 
						iStr.Length, 
						lineLen, 
						dataStr
						);
				}
			}
			else
			{
				nodeStr += baseLine;
			}
			return nodeStr + "\r\n";
		}

		private string FormatLineString(string lStr, int indent, int lineLen, string msg)
		{
			var retval = "";
			indent += indentStep;
			var realLen = lineLen - indent;
			var sLen = indent;
			int currentp;
			for (currentp = 0; currentp < msg.Length; currentp += realLen)
			{
				if (currentp+realLen > msg.Length)
				{
					retval += "\r\n" + lStr + Asn1Util.GenStr(sLen,' ') + 
						"'" + msg.Substring(currentp, msg.Length - currentp) + "'";
				}
				else
				{
					retval += "\r\n" + lStr + Asn1Util.GenStr(sLen,' ') + "'" + 
						msg.Substring(currentp, realLen) + "'";
				}
			}
			return retval;
		}

		private string FormatLineHexString(string lStr, int indent, int lineLen, string msg)
		{
			var retval = "";
			indent += indentStep;
			var realLen = lineLen - indent;
			var sLen = indent;
			int currentp;
			for (currentp = 0; currentp < msg.Length; currentp += realLen)
			{
				if (currentp+realLen > msg.Length)
				{
					retval += "\r\n" + lStr + Asn1Util.GenStr(sLen,' ') + 
						msg.Substring(currentp, msg.Length - currentp);
				}
				else
				{
					retval += "\r\n" + lStr + Asn1Util.GenStr(sLen,' ') + 
						msg.Substring(currentp, realLen);
				}
			}
			return retval;
		}

		
		//PublicMembers

		/// <summary>
		/// Constructor, initialize all the members.
		/// </summary>
		public Asn1Node()
		{
			Init();
			DataOffset = 0;
		}

		/// <summary>
		/// Get/Set isIndefiniteLength.
		/// </summary>
		public bool IsIndefiniteLength
		{
			get
			{
				return isIndefiniteLength;
			}
			set
			{
				isIndefiniteLength = value;
			}
		}

        /// <summary>
        /// Clone a new Asn1Node by current node.
        /// </summary>
        /// <returns>new node.</returns>
        public Asn1Node Clone()
        {
            var ms = new MemoryStream();
            this.SaveData(ms);
            ms.Position = 0;
            var node = new Asn1Node();
            node.LoadData(ms);
            return node;
        }

        /// <summary>
        /// Get/Set tag value.
        /// </summary>
        public byte Tag { get; set; }

        /// <summary>
        /// Load data from byte[].
        /// </summary>
        /// <param name="byteData">byte[]</param>
        /// <returns>true:Succeed; false:failed.</returns>
        public bool LoadData(byte[] byteData)
        {
            var retval = true;
            try
            {
                var ms = new MemoryStream(byteData);
                ms.Position = 0;
                retval = LoadData(ms);
                ms.Close();
            }
            catch
            {
                retval = false;
            }
            return retval;
        }

		/// <summary>
		/// Retrieve all the node count in the node subtree.
		/// </summary>
		/// <param name="node">starting node.</param>
		/// <returns>long integer node count in the node subtree.</returns>
		public static long GetDescendantNodeCount(Asn1Node node)
		{
			long count =0;
			count += node.ChildNodeCount;
			for (var i=0; i<node.ChildNodeCount; i++)
			{
				count += GetDescendantNodeCount(node.GetChildNode(i));
			}
			return count;
		}

        /// <summary>
        /// Load data from Stream. Start from current position.
        /// This function sets requireRecalculatePar to false then calls InternalLoadData 
        /// to complish the task.
        /// </summary>
        /// <param name="xdata">Stream</param>
        /// <returns>true:Succeed; false:failed.</returns>
        public bool LoadData(Stream xdata)
        {
			var retval = false;
            try
            {
                RequireRecalculatePar = false;
				retval = InternalLoadData(xdata);
                return retval;
            }
            finally
            {
                RequireRecalculatePar = true;
                RecalculateTreePar();
            }
        }

		/// <summary>
		/// Call SaveData and return byte[] as result instead stream.
		/// </summary>
		/// <returns></returns>
		public byte[] GetRawData()
		{
			var ms = new MemoryStream();
			SaveData(ms);
			var retval = new byte[ms.Length];
			ms.Position = 0;
			ms.Read(retval, 0, (int)ms.Length);
			ms.Close();
			return retval;
		}

		/// <summary>
		/// Get if data is empty.
		/// </summary>
		public bool IsEmptyData
		{
			get
			{
				if (data == null) return true;
				if (data.Length < 1)
					return true;
				else
					return false;
			}
		}

        /// <summary>
        /// Save node data into Stream.
        /// </summary>
        /// <param name="xdata">Stream.</param>
        /// <returns>true:Succeed; false:failed.</returns>
        public bool SaveData(Stream xdata)
        {
            var retval = true;
            var nodeCount = ChildNodeCount;
            xdata.WriteByte(Tag);
            var tmpLen = Asn1Util.DERLengthEncode(xdata, (ulong) DataLength);
            if ((Tag) == Asn1Tag.BIT_STRING)
            {
                xdata.WriteByte(UnusedBits);
            }
            if (nodeCount==0)
            {
                if (data != null)
                {
                    xdata.Write(data, 0, data.Length);
                }
            }
            else
            {
                Asn1Node tempNode;
                int i;
                for (i=0; i<nodeCount; i++)
                {
                    tempNode = GetChildNode(i);
                    retval = tempNode.SaveData(xdata);
                }
            }
            return retval;
        }

        /// <summary>
        /// Clear data and children list.
        /// </summary>
        public void ClearAll()
        {
            data = null;
            Asn1Node tempNode;
            for (var i=0; i<childNodeList.Count; i++)
            {
                tempNode = (Asn1Node) childNodeList[i];
                tempNode.ClearAll();
            }
            childNodeList.Clear();
            RecalculateTreePar();
        }

        
        /// <summary>
        /// Add child node at the end of children list.
        /// </summary>
        /// <param name="xdata">the node that will be add in.</param>
        public void AddChild(Asn1Node xdata)
        {
            childNodeList.Add(xdata);
            RecalculateTreePar();
        }

        /// <summary>
        /// Insert a node in the children list before the pointed index.
        /// </summary>
        /// <param name="xdata">Asn1Node</param>
        /// <param name="index">0 based index.</param>
		/// <returns>New node index.</returns>
		public int InsertChild(Asn1Node xdata, int index)
        {
            childNodeList.Insert(index, xdata);
            RecalculateTreePar();
			return index;
        }

        /// <summary>
        /// Insert a node in the children list before the pointed node.
        /// </summary>
        /// <param name="xdata">Asn1Node that will be instered in the children list.</param>
        /// <param name="indexNode">Index node.</param>
		/// <returns>New node index.</returns>
		public int InsertChild(Asn1Node xdata, Asn1Node indexNode)
        {
			var index = childNodeList.IndexOf(indexNode);
            childNodeList.Insert(index, xdata);
            RecalculateTreePar();
			return index;
        }

        /// <summary>
        /// Insert a node in the children list after the pointed node.
        /// </summary>
        /// <param name="xdata">Asn1Node</param>
        /// <param name="indexNode">Index node.</param>
		/// <returns>New node index.</returns>
		public int InsertChildAfter(Asn1Node xdata, Asn1Node indexNode)
        {
			var index = childNodeList.IndexOf(indexNode)+1;
            childNodeList.Insert(index, xdata);
            RecalculateTreePar();
			return index;
        }

        /// <summary>
        /// Insert a node in the children list after the pointed node.
        /// </summary>
        /// <param name="xdata">Asn1Node that will be instered in the children list.</param>
        /// <param name="index">0 based index.</param>
		/// <returns>New node index.</returns>
		public int InsertChildAfter(Asn1Node xdata, int index)
        {
			var xindex = index+1;
            childNodeList.Insert(xindex, xdata);
            RecalculateTreePar();
			return xindex;
        }

        /// <summary>
        /// Remove a child from children node list by index.
        /// </summary>
        /// <param name="index">0 based index.</param>
        /// <returns>The Asn1Node just removed from the list.</returns>
        public Asn1Node RemoveChild(int index)
        {
            Asn1Node retval = null;
            if (index < (childNodeList.Count - 1))
            {
                retval = (Asn1Node) childNodeList[index+1];
            }
            childNodeList.RemoveAt(index);
            if (retval == null)
            {
                if (childNodeList.Count > 0)
                {
                    retval = (Asn1Node) childNodeList[childNodeList.Count-1];
                }
                else
                {
                    retval = this;
                }
            }
            RecalculateTreePar();
            return retval;
        }

        /// <summary>
        /// Remove the child from children node list.
        /// </summary>
        /// <param name="node">The node needs to be removed.</param>
        /// <returns></returns>
        public Asn1Node RemoveChild(Asn1Node node)
        {
            Asn1Node retval = null;
            var i = childNodeList.IndexOf(node);
            retval = RemoveChild(i);
            return retval;
        }

        /// <summary>
        /// Get child node count.
        /// </summary>
        public long ChildNodeCount
        {
            get
            {
                return childNodeList.Count;
            }
        }

        /// <summary>
        /// Retrieve child node by index.
        /// </summary>
        /// <param name="index">0 based index.</param>
        /// <returns>0 based index.</returns>
        public Asn1Node GetChildNode(int index)
        {
            Asn1Node retval = null;
            if (index < ChildNodeCount)
            {
                retval = (Asn1Node) childNodeList[index];
            }
            return retval;
        }



        /// <summary>
        /// Get tag name.
        /// </summary>
        public string TagName
        {
            get
            {
                return Asn1Util.GetTagName(Tag);
            }
        }

        /// <summary>
        /// Get parent node.
        /// </summary>
        public Asn1Node ParentNode { get; private set; }

        /// <summary>
        /// Get the node and all the descendents text description.
        /// </summary>
        /// <param name="startNode">starting node.</param>
        /// <param name="lineLen">line length.</param>
        /// <returns></returns>
        public string GetText(Asn1Node startNode, int lineLen)
        {
            var nodeStr = "";
            var baseLine = "";
            var dataStr = "";
            const string lStr = "      |      |       | ";
            string oid, oidName;
            switch (Tag)
            {
                case Asn1Tag.BIT_STRING:
                    baseLine =
                        string.Format("{0,6}|{1,6}|{2,7}|{3} {4} UnusedBits:{5} : ", 
                        DataOffset, 
                        DataLength, 
                        lengthFieldBytes, 
                        GetIndentStr(startNode), 
                        TagName, 
                        UnusedBits
                        ); 
                    dataStr = Asn1Util.ToHexString(data);
                    if (baseLine.Length + dataStr.Length < lineLen)
                    {
                        if (dataStr.Length<1)
                        {
                            nodeStr += baseLine + "\r\n";
                        }
                        else
                        {
                            nodeStr += baseLine + "'" + dataStr + "'\r\n";
                        }
                    }
                    else
                    {
                        nodeStr += baseLine + FormatLineHexString(
                            lStr, 
                            GetIndentStr(startNode).Length, 
                            lineLen, 
                            dataStr + "\r\n"
                            );
                    }
                    break;
                case Asn1Tag.OBJECT_IDENTIFIER:
                    var xoid  = new Oid();
                    oid = xoid.Decode(new MemoryStream(data));
                    oidName = "foo";//xoid.GetOidName(oid);
                    nodeStr += string.Format("{0,6}|{1,6}|{2,7}|{3} {4} : {5} [{6}]\r\n", 
                        DataOffset,
                        DataLength, 
                        lengthFieldBytes, 
                        GetIndentStr(startNode), 
                        TagName, 
                        oidName,
                        oid
                        ); 
                    break;
                case Asn1Tag.RELATIVE_OID:
                    var xiod = new RelativeOid();
                    oid = xiod.Decode(new MemoryStream(data));
                    oidName = "";
                    nodeStr += string.Format("{0,6}|{1,6}|{2,7}|{3} {4} : {5} [{6}]\r\n", 
                        DataOffset,
                        DataLength, 
                        lengthFieldBytes, 
                        GetIndentStr(startNode), 
                        TagName, 
                        oidName,
                        oid
                        ); 
                    break;
                case Asn1Tag.PRINTABLE_STRING:
                case Asn1Tag.IA5_STRING:
                case Asn1Tag.UNIVERSAL_STRING:
                case Asn1Tag.VISIBLE_STRING:
                case Asn1Tag.NUMERIC_STRING:
                case Asn1Tag.UTC_TIME:
                case Asn1Tag.UTF8_STRING:
                case Asn1Tag.BMPSTRING:
				case Asn1Tag.GENERAL_STRING:
                case Asn1Tag.GENERALIZED_TIME:
                    baseLine =
                        string.Format("{0,6}|{1,6}|{2,7}|{3} {4} : ", 
                        DataOffset,
                        DataLength, 
                        lengthFieldBytes, 
                        GetIndentStr(startNode), 
                        TagName
                        );
					if ( Tag == Asn1Tag.UTF8_STRING )
					{
						var unicode = new UTF8Encoding();
						dataStr = unicode.GetString(data);
					} 
					else 
					{
						dataStr = Asn1Util.BytesToString(data);
					}
                    if (baseLine.Length + dataStr.Length < lineLen)
                    {
                        nodeStr += baseLine + "'" + dataStr + "'\r\n";
                    }
                    else
                    {
                        nodeStr += baseLine + FormatLineString(
                            lStr, 
                            GetIndentStr(startNode).Length, 
                            lineLen, 
                            dataStr) + "\r\n";
                    }
                    break;
                case Asn1Tag.INTEGER:
                    if (data != null && DataLength < 8)
                    {
                        nodeStr += string.Format("{0,6}|{1,6}|{2,7}|{3} {4} : {5}\r\n", 
                            DataOffset,
                            DataLength, 
                            lengthFieldBytes, 
                            GetIndentStr(startNode), 
                            TagName,
                            Asn1Util.BytesToLong(data).ToString()
                            );
                    }
                    else
                    {
                        baseLine =
                            string.Format("{0,6}|{1,6}|{2,7}|{3} {4} : ", 
                            DataOffset,
                            DataLength, 
                            lengthFieldBytes, 
                            GetIndentStr(startNode), 
                            TagName
                            );
                        nodeStr += GetHexPrintingStr(startNode, baseLine, lStr, lineLen);
                    }
                    break;
                default:
                    if ((Tag & Asn1Tag.TAG_MASK) == 6) // Visible string for certificate
                    {
                        baseLine =
                            string.Format("{0,6}|{1,6}|{2,7}|{3} {4} : ", 
                            DataOffset,
                            DataLength, 
                            lengthFieldBytes, 
                            GetIndentStr(startNode), 
                            TagName
                            );
                        dataStr = Asn1Util.BytesToString(data);
                        if (baseLine.Length + dataStr.Length < lineLen)
                        {
                            nodeStr += baseLine + "'" + dataStr + "'\r\n";
                        }
                        else
                        {
                            nodeStr += baseLine + FormatLineString(
                                lStr, 
                                GetIndentStr(startNode).Length, 
                                lineLen, 
                                dataStr) + "\r\n";
                        }
                    }
                    else
                    {
                        baseLine =
                            string.Format("{0,6}|{1,6}|{2,7}|{3} {4} : ", 
                            DataOffset,
                            DataLength, 
                            lengthFieldBytes, 
                            GetIndentStr(startNode), 
                            TagName
                            );
                        nodeStr += GetHexPrintingStr(startNode, baseLine, lStr, lineLen);
                    }
                    break;
            };
            if (childNodeList.Count >= 0)
            {
                nodeStr += GetListStr(startNode, lineLen);
            }
            return nodeStr;
        }

        /// <summary>
        /// Get the path string of the node.
        /// </summary>
        public string Path { get; private set; } = "";

        /// <summary>
        /// Retrieve the node description.
        /// </summary>
        /// <param name="pureHexMode">true:Return hex string only;
        /// false:Convert to more readable string depending on the node tag.</param>
        /// <returns>string</returns>
        public string GetDataStr(bool pureHexMode)
        {
            const int lineLen = 32;
            var dataStr = "";
            if (pureHexMode)
            {
                dataStr = Asn1Util.FormatString(Asn1Util.ToHexString(data), lineLen, 2);
            }
            else
            {
                switch (Tag)
                {
                    case Asn1Tag.BIT_STRING:
                        dataStr = Asn1Util.FormatString(Asn1Util.ToHexString(data), lineLen, 2);
                        break;
                    case Asn1Tag.OBJECT_IDENTIFIER:
                        var xoid = new Oid();
                        dataStr = xoid.Decode(new MemoryStream(data));
                        break;
                    case Asn1Tag.RELATIVE_OID:
                        var roid = new RelativeOid();
                        dataStr = roid.Decode(new MemoryStream(data));
                        break;
                    case Asn1Tag.PRINTABLE_STRING:
                    case Asn1Tag.IA5_STRING:
                    case Asn1Tag.UNIVERSAL_STRING:
                    case Asn1Tag.VISIBLE_STRING:
                    case Asn1Tag.NUMERIC_STRING:
                    case Asn1Tag.UTC_TIME:
                    case Asn1Tag.BMPSTRING:
					case Asn1Tag.GENERAL_STRING:
                    case Asn1Tag.GENERALIZED_TIME:
                        dataStr = Asn1Util.BytesToString(data);
                        break;
					case Asn1Tag.UTF8_STRING:
						var utf8 = new UTF8Encoding();
						dataStr = utf8.GetString(data);
						break;
					case Asn1Tag.INTEGER:
                        dataStr = Asn1Util.FormatString(Asn1Util.ToHexString(data), lineLen, 2);
                        break;
                    default:
                        if ((Tag & Asn1Tag.TAG_MASK) == 6) // Visible string for certificate
                        {
                            dataStr = Asn1Util.BytesToString(data);
                        }
                        else
                        {
                            dataStr = Asn1Util.FormatString(Asn1Util.ToHexString(data), lineLen, 2);
                        }
                        break;
                };
            }
            return dataStr;
        }

        /// <summary>
        /// Get node label string.
        /// </summary>
        /// <param name="mask">
        /// <code>
		/// SHOW_OFFSET
		/// SHOW_DATA
		/// USE_HEX_OFFSET
		/// SHOW_TAG_NUMBER
		/// SHOW_PATH</code>
		/// </param>
        /// <returns>string</returns>
        public string GetLabel(uint mask)
        {
            var nodeStr = "";
            var dataStr = "";
            var offsetStr = "";
            if ((mask & TagTextMask.USE_HEX_OFFSET) != 0)
            {
                if ((mask & TagTextMask.SHOW_TAG_NUMBER) != 0)
                    offsetStr = string.Format("(0x{0:X2},0x{1:X6},0x{2:X4})", Tag, DataOffset, DataLength);
                else
                    offsetStr = string.Format("(0x{0:X6},0x{1:X4})", DataOffset, DataLength);
            }
            else
            {
                if ((mask & TagTextMask.SHOW_TAG_NUMBER) != 0)
                    offsetStr = string.Format("({0},{1},{2})", Tag, DataOffset, DataLength);
                else
                    offsetStr = string.Format("({0},{1})", DataOffset, DataLength);
            }
            string oid, oidName;
            switch (Tag)
            {
                case Asn1Tag.BIT_STRING:
                    if ((mask & TagTextMask.SHOW_OFFSET) != 0)
                    {
                        nodeStr += offsetStr;
                    }
                    nodeStr += " " + TagName + " UnusedBits: " + UnusedBits.ToString();
                    if ((mask & TagTextMask.SHOW_DATA) != 0)
                    {
                        dataStr = Asn1Util.ToHexString(data);
                        nodeStr += ((dataStr.Length>0) ? " : '" + dataStr + "'" : "");
                    }
                    break;
                case Asn1Tag.OBJECT_IDENTIFIER:
                    var xoid = new Oid();
                    oid = xoid.Decode(data);
                    oidName = "bar";// xoid.GetOidName(oid);
                    if ((mask & TagTextMask.SHOW_OFFSET) != 0)
                    {
                        nodeStr += offsetStr;
                    }
                    nodeStr += " " + TagName;
                    nodeStr += " : " + oidName;
                    if ((mask & TagTextMask.SHOW_DATA) != 0)
                    {
                        nodeStr += ((oid.Length>0) ? " : '" + oid + "'" : "");
                    }
                    break;
                case Asn1Tag.RELATIVE_OID:
                    var roid = new RelativeOid();
                    oid = roid.Decode(data);
                    oidName = "";
                    if ((mask & TagTextMask.SHOW_OFFSET) != 0)
                    {
                        nodeStr += offsetStr;
                    }
                    nodeStr += " " + TagName;
                    nodeStr += " : " + oidName;
                    if ((mask & TagTextMask.SHOW_DATA) != 0)
                    {
                        nodeStr += ((oid.Length>0) ? " : '" + oid + "'" : "");
                    }
                    break;
                case Asn1Tag.PRINTABLE_STRING:
                case Asn1Tag.IA5_STRING:
                case Asn1Tag.UNIVERSAL_STRING:
                case Asn1Tag.VISIBLE_STRING:
                case Asn1Tag.NUMERIC_STRING:
                case Asn1Tag.UTC_TIME:
                case Asn1Tag.UTF8_STRING:
                case Asn1Tag.BMPSTRING:
				case Asn1Tag.GENERAL_STRING:
                case Asn1Tag.GENERALIZED_TIME:
                    if ((mask & TagTextMask.SHOW_OFFSET) != 0)
                    {
                        nodeStr += offsetStr;
                    }
                    nodeStr += " " + TagName;
                    if ((mask & TagTextMask.SHOW_DATA) != 0)
                    {
						if ( Tag == Asn1Tag.UTF8_STRING )
						{
							var unicode = new UTF8Encoding();
							dataStr = unicode.GetString(data);
						} 
						else 
						{
							dataStr = Asn1Util.BytesToString(data);
						}
						nodeStr += ((dataStr.Length>0) ? " : '" + dataStr + "'" : "");
                    }
                    break;
                case Asn1Tag.INTEGER:
                    if ((mask & TagTextMask.SHOW_OFFSET) != 0)
                    {
                        nodeStr += offsetStr;
                    }
                    nodeStr += " " + TagName;
                    if ((mask & TagTextMask.SHOW_DATA) != 0)
                    {
                        if (data != null && DataLength < 8)
                        {
                            dataStr = Asn1Util.BytesToLong(data).ToString();
                        }
                        else
                        {
                            dataStr = Asn1Util.ToHexString(data);
                        }
                        nodeStr += ((dataStr.Length>0) ? " : '" + dataStr + "'" : "");
                    }
                    break;
                default:
                    if ((mask & TagTextMask.SHOW_OFFSET) != 0)
                    {
                        nodeStr += offsetStr;
                    }
                    nodeStr += " " + TagName;
                    if ((mask & TagTextMask.SHOW_DATA) != 0)
                    {
                        if ((Tag & Asn1Tag.TAG_MASK) == 6) // Visible string for certificate
                        {
                            dataStr = Asn1Util.BytesToString(data);
                        }
                        else
                        {
                            dataStr = Asn1Util.ToHexString(data);
                        }
                        nodeStr += ((dataStr.Length>0) ? " : '" + dataStr + "'" : "");
                    }
                    break;
            };
            if ((mask & TagTextMask.SHOW_PATH) != 0)
            {
                nodeStr = "(" + Path + ") " + nodeStr;
            }
            return nodeStr;
        }

        /// <summary>
        /// Get data length. Not included the unused bits byte for BITSTRING.
        /// </summary>
        public long DataLength { get; private set; }

        /// <summary>
        /// Get the length field bytes.
        /// </summary>
        public long LengthFieldBytes
        {
            get
            {
                return lengthFieldBytes;
            }
        }

        /// <summary>
        /// Get/Set node data by byte[], the data length field content and all the 
        /// node in the parent chain will be adjusted.
        /// <br></br>
        /// It return all the child data for constructed node.
        /// </summary>
        public byte[] Data
        {
            get
            {
				var xdata = new MemoryStream();
				var nodeCount = ChildNodeCount;
				if (nodeCount==0)
				{
					if (data != null)
					{
						xdata.Write(data, 0, data.Length);
					}
				}
				else
				{
					Asn1Node tempNode;
					for (var i=0; i<nodeCount; i++)
					{
						tempNode = GetChildNode(i);
						tempNode.SaveData(xdata);
					}
				}
				var tmpData = new byte[xdata.Length];
				xdata.Position = 0;
				xdata.Read(tmpData, 0, (int)xdata.Length);
				xdata.Close();
				return tmpData;
            }
            set
            {
                SetData(value);
            }
        }

        /// <summary>
        /// Get the deepness of the node.
        /// </summary>
        public long Deepness { get; private set; }

        /// <summary>
        /// Get data offset.
        /// </summary>
        public long DataOffset { get; private set; }

        /// <summary>
        /// Get unused bits for BITSTRING.
        /// </summary>
        public byte UnusedBits { get; set; }


        /// <summary>
        /// Get descendant node by node path.
        /// </summary>
        /// <param name="nodePath">relative node path that refer to current node.</param>
        /// <returns></returns>
        public Asn1Node GetDescendantNodeByPath(string nodePath)
        {
            var retval = this;
            if (nodePath == null) return retval;
            nodePath = nodePath.TrimEnd().TrimStart();
            if (nodePath.Length<1) return retval;
            var route = nodePath.Split('/');
            try
            {
                for (var i = 1; i<route.Length; i++)
                {
                    retval = retval.GetChildNode(Convert.ToInt32(route[i]));
                }
            }
            catch
            {
                retval = null;
            }
            return retval;
        }

		/// <summary>
		/// Get node by OID.
		/// </summary>
		/// <param name="oid">OID.</param>
		/// <param name="startNode">Starting node.</param>
		/// <returns>Null or Asn1Node.</returns>
		static public Asn1Node GetDecendantNodeByOid(string oid, Asn1Node startNode)
		{
			Asn1Node retval = null;
            var xoid = new Oid();
			for (var i = 0; i<startNode.ChildNodeCount; i++)
			{
				var childNode = startNode.GetChildNode(i);
				var tmpTag = childNode.Tag & Asn1Tag.TAG_MASK;
				if (tmpTag == Asn1Tag.OBJECT_IDENTIFIER)
				{
					if (oid == xoid.Decode(childNode.Data))
					{
						retval = childNode;
						break;
					}
				}
				retval = GetDecendantNodeByOid(oid, childNode);
				if (retval != null) break;
			}
			return retval;
		}
        
        /// <summary>
        /// Constant of tag field length.
        /// </summary>
        public const int TagLength = 1;

        /// <summary>
        /// Constant of unused bits field length.
        /// </summary>
        public const int BitStringUnusedFiledLength = 1;

        /// <summary>
        /// Tag text generation mask definition.
        /// </summary>
        public class TagTextMask
        {
            /// <summary>
            /// Show offset.
            /// </summary>
            public const uint SHOW_OFFSET			= 0x01;

            /// <summary>
            /// Show decoded data.
            /// </summary>
            public const uint SHOW_DATA			    = 0x02;

            /// <summary>
            /// Show offset in hex format.
            /// </summary>
            public const uint USE_HEX_OFFSET		= 0x04;

            /// <summary>
            /// Show tag.
            /// </summary>
            public const uint SHOW_TAG_NUMBER		= 0x08;

            /// <summary>
            /// Show node path.
            /// </summary>
            public const uint SHOW_PATH             = 0x10;
        }

        /// <summary>
        /// Set/Get requireRecalculatePar. RecalculateTreePar function will not do anything
        /// if it is set to false. 
        /// </summary>
        protected bool RequireRecalculatePar { get; set; } = true;

        //ProtectedMembers

        /// <summary>
        /// Find root node and recalculate entire tree length field, 
        /// path, offset and deepness.
        /// </summary>
        protected void RecalculateTreePar()
        {
            if (!RequireRecalculatePar) return;
            Asn1Node rootNode;
            for (rootNode = this; rootNode.ParentNode != null;)
            {
                rootNode = rootNode.ParentNode;
            }
            ResetBranchDataLength(rootNode);
            rootNode.DataOffset = 0;
            rootNode.Deepness = 0;
            var subOffset = rootNode.DataOffset + TagLength + rootNode.lengthFieldBytes;
            ResetChildNodePar(rootNode, subOffset);
        }

        /// <summary>
        /// Recursively set all the node data length.
        /// </summary>
        /// <param name="node"></param>
        /// <returns>node data length.</returns>
        protected static long ResetBranchDataLength(Asn1Node node)
        {
            long retval = 0;
            long childDataLength = 0;
            if (node.ChildNodeCount < 1)
            {
                if (node.data != null)
                    childDataLength += node.data.Length;
            }
            else
            {
                for (var i=0; i<node.ChildNodeCount; i++)
                {
                    childDataLength += ResetBranchDataLength(node.GetChildNode(i));
                }
            }
            node.DataLength = childDataLength;
            if (node.Tag == Asn1Tag.BIT_STRING)
                node.DataLength += BitStringUnusedFiledLength;
            ResetDataLengthFieldWidth(node);
            retval = node.DataLength + TagLength + node.lengthFieldBytes;
            return retval;
        }

        /// <summary>
        /// Encode the node data length field and set lengthFieldBytes and dataLength.
        /// </summary>
        /// <param name="node">The node needs to be reset.</param>
        protected static void ResetDataLengthFieldWidth(Asn1Node node)
        {
            var tempStream = new MemoryStream();
            Asn1Util.DERLengthEncode(tempStream, (ulong) node.DataLength);
            node.lengthFieldBytes = tempStream.Length;
            tempStream.Close();
        }

        /// <summary>
        /// Recursively set all the child parameters, except dataLength.
        /// dataLength is set by ResetBranchDataLength.
        /// </summary>
        /// <param name="xNode">Starting node.</param>
        /// <param name="subOffset">Starting node offset.</param>
        protected void ResetChildNodePar(Asn1Node xNode, long subOffset)
        {
            int i;
            if (xNode.Tag == Asn1Tag.BIT_STRING)
            {
                subOffset++;
            }
            Asn1Node tempNode;
            for (i=0; i<xNode.ChildNodeCount; i++)
            {
                tempNode = xNode.GetChildNode(i);
                tempNode.ParentNode = xNode;
                tempNode.DataOffset = subOffset;
                tempNode.Deepness = xNode.Deepness + 1;
                tempNode.Path = xNode.Path + '/' + i.ToString();
                subOffset += TagLength + tempNode.lengthFieldBytes;
                ResetChildNodePar(tempNode, subOffset);
                subOffset += tempNode.DataLength;
            }
        }

        /// <summary>
        /// Generate all the child text from childNodeList.
        /// </summary>
        /// <param name="startNode">Starting node.</param>
        /// <param name="lineLen">Line length.</param>
        /// <returns>Text string.</returns>
        protected string GetListStr(Asn1Node startNode, int lineLen)
        {
            var nodeStr = "";
            int i;
            Asn1Node tempNode;
            for (i=0; i<childNodeList.Count; i++)
            {
                tempNode = (Asn1Node) childNodeList[i];
                nodeStr += tempNode.GetText(startNode, lineLen);
            }
            return nodeStr;
        }

        /// <summary>
        /// Generate the node indent string.
        /// </summary>
        /// <param name="startNode">The node.</param>
        /// <returns>Text string.</returns>
        protected string GetIndentStr(Asn1Node startNode)
        {
            var retval = "";
            long startLen = 0;
            if (startNode!=null)
            {
                startLen = startNode.Deepness;
            }
            for (long i = 0; i<Deepness - startLen; i++)
            {
                retval += "   ";
            }
            return retval;
        }

        /// <summary>
        /// Decode ASN.1 encoded node Stream data.
        /// </summary>
        /// <param name="xdata">Stream data.</param>
        /// <returns>true:Succeed, false:Failed.</returns>
        protected bool GeneralDecode(Stream xdata)
        {
            var retval = false;
            long nodeMaxLen;
            nodeMaxLen = xdata.Length - xdata.Position;
            Tag = (byte) xdata.ReadByte();
            long start, end;
            start = xdata.Position;
            DataLength = Asn1Util.DerLengthDecode(xdata, ref isIndefiniteLength);
            if (DataLength < 0) return retval; // Node data length can not be negative.
            end = xdata.Position;
            lengthFieldBytes = end - start;
            if (nodeMaxLen < (DataLength + TagLength + lengthFieldBytes))
            {
                return retval;
            }
            if ( ParentNode == null || ((ParentNode.Tag & Asn1TagClasses.CONSTRUCTED) == 0))
            {
                if ((Tag & Asn1Tag.TAG_MASK)<=0 || (Tag & Asn1Tag.TAG_MASK)>0x1E) return retval;
            }
            if (Tag == Asn1Tag.BIT_STRING)
            {
                // First byte of BIT_STRING is unused bits.
                // BIT_STRING data does not include this byte.

                // Fixed by Gustaf Björklund.
                if (DataLength < 1) return retval; // We cannot read less than 1 - 1 bytes.

                UnusedBits = (byte) xdata.ReadByte();
                data = new byte[DataLength-1];
                xdata.Read(data, 0, (int)(DataLength-1) );
            }
            else
            {
                data = new byte[DataLength];
                xdata.Read(data, 0, (int)(DataLength) );
            }
            retval = true;
            return retval;
        }

        /// <summary>
        /// Decode ASN.1 encoded complex data type Stream data.
        /// </summary>
        /// <param name="xdata">Stream data.</param>
        /// <returns>true:Succeed, false:Failed.</returns>
        protected bool ListDecode(Stream xdata)
        {
            var retval = false;
            var originalPosition = xdata.Position;
            long childNodeMaxLen;
            try
            {
                childNodeMaxLen = xdata.Length - xdata.Position;
                Tag = (byte) xdata.ReadByte();
                long start, end, offset;
                start = xdata.Position;
                DataLength = Asn1Util.DerLengthDecode(xdata, ref isIndefiniteLength);
                if (DataLength<0 || childNodeMaxLen<DataLength)
                {
                    return retval;
                }
                end = xdata.Position;
                lengthFieldBytes = end - start;
                offset = DataOffset + TagLength + lengthFieldBytes;
                Stream secData;
                byte[] secByte;
                if (Tag == Asn1Tag.BIT_STRING)
                {
                    // First byte of BIT_STRING is unused bits.
                    // BIT_STRING data does not include this byte.
                    UnusedBits = (byte) xdata.ReadByte();
                    DataLength--;
                    offset++;
                }
                if (DataLength <= 0) return retval; // List data length cann't be zero.
                secData = new MemoryStream((int)DataLength);
                secByte = new byte[DataLength];
                xdata.Read(secByte, 0, (int) (DataLength));
                if (Tag == Asn1Tag.BIT_STRING) DataLength++;
                secData.Write(secByte, 0, secByte.Length);
                secData.Position = 0;
                while(secData.Position<secData.Length)
                {
                    var node = new Asn1Node(this, offset);
					node.parseEncapsulatedData = this.parseEncapsulatedData;
                    start = secData.Position;
                    if (!node.InternalLoadData(secData)) return retval;
                    AddChild(node);
                    end = secData.Position;
                    offset += end - start;
                }
                retval = true;
            }
            finally
            {
                if (!retval)
                {
                    xdata.Position = originalPosition;
                    ClearAll();
                }
            }
            return retval;
        }

        /// <summary>
        /// Set the node data and recalculate the entire tree parameters.
        /// </summary>
        /// <param name="xdata">byte[] data.</param>
        protected void SetData(byte[] xdata)
        {
			if (childNodeList.Count > 0)
			{
				throw new Exception("Constructed node can't hold simple data.");
			}
			else
			{
				data = xdata;
				if (data != null)
					DataLength = data.Length;
				else
					DataLength = 0;
				RecalculateTreePar();
			}
        }

        /// <summary>
        /// Load data from Stream. Start from current position.
        /// </summary>
        /// <param name="xdata">Stream</param>
        /// <returns>true:Succeed; false:failed.</returns>
        protected bool InternalLoadData(Stream xdata)
        {
            var retval = true;
            ClearAll();
            byte xtag; 
            var curPosition = xdata.Position;
            xtag = (byte) xdata.ReadByte();
            xdata.Position = curPosition;
            var maskedTag = xtag & Asn1Tag.TAG_MASK;
            if (((xtag & Asn1TagClasses.CONSTRUCTED) != 0) 
                || (parseEncapsulatedData 
				&& ((maskedTag == Asn1Tag.BIT_STRING)
                || (maskedTag == Asn1Tag.EXTERNAL)
                || (maskedTag == Asn1Tag.GENERAL_STRING)
                || (maskedTag == Asn1Tag.GENERALIZED_TIME)
                || (maskedTag == Asn1Tag.GRAPHIC_STRING)
                || (maskedTag == Asn1Tag.IA5_STRING)
                || (maskedTag == Asn1Tag.OCTET_STRING)
                || (maskedTag == Asn1Tag.PRINTABLE_STRING)
                || (maskedTag == Asn1Tag.SEQUENCE)
                || (maskedTag == Asn1Tag.SET)
                || (maskedTag == Asn1Tag.T61_STRING)
                || (maskedTag == Asn1Tag.UNIVERSAL_STRING)
                || (maskedTag == Asn1Tag.UTF8_STRING)
                || (maskedTag == Asn1Tag.VIDEOTEXT_STRING)
                || (maskedTag == Asn1Tag.VISIBLE_STRING)))
                )
            {
                if (!ListDecode(xdata))
                {
                    if (!GeneralDecode(xdata))
                    {
                        retval = false;
                    }
                }
            }
            else
            {
                if (!GeneralDecode(xdata)) retval = false;
            }
            return retval;
        }

		/// <summary>
		/// Get/Set parseEncapsulatedData. This property will be inherited by the 
		/// child nodes when loading data.
		/// </summary>
		public bool ParseEncapsulatedData 
		{ 
			get
			{
				return parseEncapsulatedData;
			}
			set
			{
				if (parseEncapsulatedData == value) return;
				var tmpData = Data;
				parseEncapsulatedData = value;
				ClearAll();
				if ((Tag & Asn1TagClasses.CONSTRUCTED) != 0 || parseEncapsulatedData)
				{
					var ms = new MemoryStream(tmpData);
					ms.Position = 0;
					var isLoaded = true;
					while(ms.Position < ms.Length)
					{
						var tempNode = new Asn1Node();
						tempNode.ParseEncapsulatedData = parseEncapsulatedData;
						if (!tempNode.LoadData(ms))
						{
							ClearAll();
							isLoaded = false;
							break;
						}
						AddChild(tempNode);
					}
					if (!isLoaded)
					{
						Data = tmpData;
					}
				}
				else
				{
					Data = tmpData;
				}
			}
		}

    }

}

