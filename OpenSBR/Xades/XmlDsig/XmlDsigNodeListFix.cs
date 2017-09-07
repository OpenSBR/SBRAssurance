using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenSBR.Xades
{
	public class XmlDsigXPathTransformFix : XmlDsigXPathTransform
	{
		public XmlDsigXPathTransformFix() : base()
		{ }

		public XmlDsigXPathTransformFix(string transform, Dictionary<string, string> namespaces = null) : base()
		{
			FieldInfo xpathexprInfo = typeof(XmlDsigXPathTransform).GetField("_xpathexpr", BindingFlags.NonPublic | BindingFlags.Instance);
			xpathexprInfo.SetValue(this, transform);

			XmlNamespaceManager nsm = new XmlNamespaceManager(new NameTable());
			if (namespaces != null)
				foreach (KeyValuePair<string, string> ns in namespaces)
					nsm.AddNamespace(ns.Key, ns.Value);

			FieldInfo nsmInfo = typeof(XmlDsigXPathTransform).GetField("_nsm", BindingFlags.NonPublic | BindingFlags.Instance);
			nsmInfo.SetValue(this, nsm);
		}

		public override object GetOutput()
		{
			FieldInfo documentInfo = typeof(XmlDsigXPathTransform).GetField("_document", BindingFlags.NonPublic | BindingFlags.Instance);
			XmlDocument document = (XmlDocument)documentInfo.GetValue(this);
			object cXmlNodeList = base.GetOutput();
			XmlDsigWorkaround.FixDocument(document, (XmlNodeList)cXmlNodeList);
			return cXmlNodeList;
		}
	}

	/// <summary>
	/// Static function to work around a bug in the .NET framework
	/// When removing/omitting parent nodes with xml-namespace attributes from the result through an XPath transform (or the filter above),
	/// the framework propagates these attributes to ALL child nodes, instead of just the top level ones.
	/// This function copies these xml nodes to the top level nodes in the selection, after which the attributes from the nodes outside the selection are removed.
	/// This way, the .NET transform chain code no longer finds any xml-namespace attributes to propagate.
	/// </summary>
	public class XmlDsigWorkaround
	{
		public static void FixDocument(XmlDocument document, XmlNodeList nodeList)
		{
			XmlDsigWorkaround workaround = new XmlDsigWorkaround();
			workaround._nodeSet = new HashSet<XmlNode>(nodeList.OfType<XmlNode>());
			workaround._document = document;
			workaround.IterateNodes(document, null);
		}

		private XmlDocument _document;
		private HashSet<XmlNode> _nodeSet;

		private void IterateNodes(XmlNode node, Dictionary<string, string> attributes)
		{
			// flag to determine if creating a copy of the attribute list is necessary
			bool altered = false;

			// check if node is an element
			if (node.NodeType == XmlNodeType.Element)
			{
				if (_nodeSet.Contains(node))
				{
					// if node is in selection:
					//  add all stored attributes from previous levels to the current node
					//  reset attribute collection for children
					if (attributes != null)
					{
						foreach (KeyValuePair<string, string> attribute in attributes)
						{
							XmlAttribute xmlAttribute = _document.CreateAttribute("xml", attribute.Key, "http://www.w3.org/XML/1998/namespace");
							xmlAttribute.Value = attribute.Value;
							((XmlElement)node).SetAttributeNode(xmlAttribute);
						}
					}
					attributes = null;
				}
				else
				{
					// if node is not in selection:
					//  add all xml-namespace attributes to collection
					//  remove attribute from node
					for (int i = 0; i < node.Attributes.Count; i++)
					{
						XmlAttribute attribute = node.Attributes[i];
						if (attribute.NamespaceURI == "http://www.w3.org/XML/1998/namespace")
						{
							// if this is the first change to the attribute collection on this level, clone the collection (so the collection for the previous level remains unaltered)
							if (!altered)
							{
								attributes = attributes != null ? new Dictionary<string, string>(attributes) : new Dictionary<string, string>();
								altered = true;
							}
							// add attribute to collection
							attributes[attribute.LocalName] = attribute.Value;
							// remove attribute from node
							((XmlElement)node).RemoveAttributeAt(i);
							// alter index to account for deleted attribute
							i--;
						}
					}
				}
			}
			// iterate over children with the attributes collected for this level
			foreach (XmlNode child in node.ChildNodes)
				IterateNodes(child, attributes);
		}
	}
}
