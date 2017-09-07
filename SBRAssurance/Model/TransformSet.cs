using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;

namespace SBRAssurance.Model
{
	public class TransformSet
	{
		public string Name { get; private set; }
		public string[] DefaultFor { get; private set; }

		/// <summary>
		/// Create empty entry
		/// </summary>
		public TransformSet()
		{
			Name = "None";
		}

		/// <summary>
		/// Create new set from XML
		/// </summary>
		/// <param name="element"></param>
		public TransformSet(XmlElement element)
		{
			Name = element.Attributes["name"]?.Value;
			DefaultFor = element.Attributes["defaultfor"]?.Value?.Split(new char[] { ',', ';', ' ' }, StringSplitOptions.RemoveEmptyEntries);

			TransformChain = new TransformChain();
			foreach (XmlElement xmlElement in element.ChildNodes)
			{
				string attribute = xmlElement.GetAttribute("Algorithm");
				Transform transform = CryptoConfig.CreateFromName(attribute) as Transform;
				if (transform != null)
				{
					transform.LoadInnerXml(xmlElement.ChildNodes);
					TransformChain.Add(transform);
				}
			}
		}

		public TransformChain TransformChain { get; private set; }
	}
}
