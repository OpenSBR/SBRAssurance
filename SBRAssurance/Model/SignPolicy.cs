using System.Linq;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace SBRAssurance.Model
{
	public class SignPolicy
	{
		private string _url;

		private string _policyDigest;
		private TransformChain _transformChain;

		private string _policyId;
		private string _policyDescription;

		private string[] _allowedMethods;

		private CommitmentType[] _commitmentTypes;

		/// <summary>
		/// Simple parser of signature policy
		/// 
		/// This is a very rough implementation aimed at getting the required information in a version-independent manner
		/// </summary>
		/// <param name="url"></param>
		/// <param name="preferredLanguage"></param>
		public SignPolicy(string url, string preferredLanguage)
		{
			XmlDocument document = new XmlDocument();
			document.Load(url);
			_url = url;

			XmlNamespaceManager nsm = new XmlNamespaceManager(new NameTable());
			nsm.AddNamespace("sbrsp", document.SelectSingleNode("/*")?.NamespaceURI);
			nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
			nsm.AddNamespace("xades", OpenSBR.Xades.XadesSignature.XadesNamespaceUrl);

			// signature policy digest information
			XmlElement policyDigest = document.SelectSingleNode("//sbrsp:SignPolicyDigestAlg", nsm) as XmlElement;
			_policyDigest = policyDigest?.GetAttribute("Algorithm");
			XmlElement transformChain = document.SelectSingleNode("//ds:Transforms", nsm) as XmlElement;
			if (transformChain != null)
			{
				_transformChain = new TransformChain();
				MethodInfo loadXmlInfo = typeof(TransformChain).GetMethod("LoadXml", BindingFlags.NonPublic | BindingFlags.Instance);
				loadXmlInfo.Invoke(_transformChain, new object[] { transformChain });
			}

			// policy identifier and description
			XmlElement policyId = document.SelectSingleNode("//sbrsp:SignPolicyIdentifier/*[local-name()='Identifier']", nsm) as XmlElement;
			_policyId = policyId?.InnerText;
			XmlElement policyDescription = document.SelectSingleNode($"//sbrsp:SignPolicyIdentifier/*[local-name()='Description' and @xml:lang='{preferredLanguage}']", nsm) as XmlElement;
			if (policyDescription == null)
				policyDescription = document.SelectNodes("//sbrsp:SignPolicyIdentifier/*[local-name()='Description']", nsm)?.Item(0) as XmlElement;
			_policyDescription = policyDescription?.InnerText;

			// supported algorithms
			_allowedMethods = document.SelectNodes("//sbrsp:SignerAlgConstraints/sbrsp:AlgAndLength/sbrsp:AlgId", nsm).OfType<XmlElement>().Select(x => x?.InnerText).ToArray();

			// commitment types
			_commitmentTypes = document.SelectNodes("//sbrsp:SelCommitmentType/sbrsp:RecognizedCommitmentType/sbrsp:CommitmentIdentifier", nsm).OfType<XmlElement>().Select(x => new CommitmentType(x, nsm, preferredLanguage)).ToArray();

			// wrong value in http://nltaxonomie.nl/sbr/signature_policy_schema/v1.0/SBR-signature-policy-v1.0.xml
			if (_policyId == "urn:sbr:signature-policy:xml:1.0")
				_policyDigest = SignedXml.XmlDsigSHA256Url;
		}

		public string URL
		{
			get { return _url; }
		}

		public string PolicyDigest
		{
			get { return _policyDigest; }
		}

		public TransformChain TransformChain
		{
			get { return _transformChain; }
		}

		public string Id
		{
			get { return _policyId; }
		}

		public string Description
		{
			get { return _policyDescription; }
		}

		public string[] DigestMethods
		{
			get { return _allowedMethods; }
		}

		public CommitmentType[] CommitmentTypes
		{
			get { return _commitmentTypes; }
		}
	}

	public class CommitmentType
	{
		private string _commitmentTypeId;
		private string _commitmentTypeDescription;

		public CommitmentType(XmlElement commitmentIdentifier, XmlNamespaceManager nsm, string preferredLanguage)
		{
			XmlElement identifier = commitmentIdentifier.SelectSingleNode("*[local-name()='Identifier']", nsm) as XmlElement;
			_commitmentTypeId = identifier?.InnerText;
			XmlElement description = commitmentIdentifier.SelectSingleNode($"*[local-name()='Description' and @xml:lang='{preferredLanguage}']", nsm) as XmlElement;
			if (description == null)
				description = commitmentIdentifier.SelectNodes("*[local-name()='Description']", nsm)?.Item(0) as XmlElement;
			_commitmentTypeDescription = description?.InnerText;
		}

		public string Id
		{
			get { return _commitmentTypeId; }
		}

		public string Description
		{
			get { return _commitmentTypeDescription; }
		}
	}
}
