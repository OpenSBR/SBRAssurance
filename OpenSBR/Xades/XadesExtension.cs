using System;
using System.Xml;

namespace OpenSBR.Xades
{
	internal static class XadesXmlExtension
	{
		internal static XmlElement CreateChild(this XmlElement element, string name, string namespaceURI)
		{
			XmlElement child = element.OwnerDocument.CreateElement(name, namespaceURI);
			element.AppendChild(child);
			return child;
		}

		internal static string GetInnerText(this XmlElement element, string xpath, XmlNamespaceManager nsm)
		{
			XmlElement child = element?.SelectSingleNode(xpath, nsm) as XmlElement;
			return child?.InnerText;
		}
	}
}
