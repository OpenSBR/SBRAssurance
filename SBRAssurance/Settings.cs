using SBRAssurance.Model;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Serialization;

namespace SBRAssurance
{
	public class Settings
	{
		public static Settings Load()
		{
			string filename = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Settings.xml");

			XmlDocument document = new XmlDocument();
			document.Load(filename);

			Settings settings = new Settings();

			// create list of transforms, with default ampty entry
			settings.TransformSets = new List<TransformSet>();
			settings.TransformSets.Add(new TransformSet());
			foreach (XmlElement transformSet in document.SelectNodes("SBRAssuranceSettings/TransformSets/Transforms"))
				settings.TransformSets.Add(new TransformSet(transformSet));

			settings.PreferredLanguage = document.SelectSingleNode("SBRAssuranceSettings/PreferredLanguage")?.Value ?? "en";
			settings.PolicyURLs = document.SelectNodes("SBRAssuranceSettings/SignaturePolicies/SignaturePolicy").OfType<XmlElement>().Select(x => x.InnerText).ToArray();

			return settings;
		}

		public List<TransformSet> TransformSets { get; set; }
		public string PreferredLanguage { get; set; }
		public string[] PolicyURLs { get; set; }
	}
}
