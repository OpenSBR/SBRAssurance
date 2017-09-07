using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace OpenSBR.Xades
{
	public class XadesSignature
	{
		public static string XadesNamespaceUrl = "http://uri.etsi.org/01903/v1.3.2#";
		public static string XadesReferenceType = "http://uri.etsi.org/01903#SignedProperties";     // Xades specification requires "http://uri.etsi.org/01903/v1.1.1#SignedProperties" but the receiving party currently does not accept this value
		public static string XadesSignedPropertiesId = "signed-properties";
		public static string XadesSignatureRootId = "signature-root";

		public delegate Stream UriResolver(string uri);

		private XmlDocument _document;
		private SignedXml _signedXml;

		private XmlElement _signedProperties;
		private Reference _signedPropertiesReference;
		private XadesSignatureProperties _signatureProperties;

		private TransformChain _xadesTransformChain;
		private string _xadesDigestMethod;

		private List<XadesFile> _xadesFiles;

		private bool _validSignedInfo;
		private bool _validSignedProperties;

		/// <summary>
		/// Static constructor to add xmldsig-filter2 and apply nodelist fixes
		/// </summary>
		static XadesSignature()
		{
			CryptoConfig.AddAlgorithm(typeof(XmlDsigFilterTransform), new string[] { "http://www.w3.org/2002/06/xmldsig-filter2" });
			CryptoConfig.AddAlgorithm(typeof(XmlDsigXPathTransformFix), new string[] { SignedXml.XmlDsigXPathTransformUrl });
		}

		/// <summary>
		/// Allows for manual initialization (forces invocation of static constructor)
		/// This would only be useful in case Transforms are parsed before a XadesSignature instance is created
		/// </summary>
		public static void Init()
		{ }

		/// <summary>
		/// Create a signature document
		/// </summary>
		public XadesSignature()
		{
			// create a document with a root node to attach to the .NET SignedXml instance (necessary to locate the Xades reference id later on)
			_document = new XmlDocument();
			_document.AppendChild(_document.CreateElement("Object", SignedXml.XmlDsigNamespaceUrl));

			_signedXml = new SignedXml(_document);
			_signatureProperties = new XadesSignatureProperties();
			_xadesFiles = new List<XadesFile>();

			// set defaults
			CanonicalizationMethod = SignedXml.XmlDsigC14NWithCommentsTransformUrl;
			SignatureMethod = SignedXml.XmlDsigRSASHA256Url;
			_xadesTransformChain = new TransformChain();
			_xadesTransformChain.Add(new XmlDsigC14NWithCommentsTransform());
			_xadesDigestMethod = SignedXml.XmlDsigSHA256Url;
		}

		/// <summary>
		/// Create new instance from existing document - allows signature checking
		/// </summary>
		/// <param name="signatureStream"></param>
		public XadesSignature(Stream signatureStream)
		{
			XmlDocument document = new XmlDocument();
			document.Load(signatureStream);
			_signedXml = new SignedXml(document);
			_signedXml.LoadXml(document.DocumentElement);

			XmlNamespaceManager nsm = new XmlNamespaceManager(new NameTable());
			nsm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
			nsm.AddNamespace("xades", XadesSignature.XadesNamespaceUrl);

			// find the xades reference
			_xadesFiles = new List<XadesFile>();
			foreach (Reference reference in _signedXml.SignedInfo.References)
			{
				if (reference.Type == XadesSignature.XadesReferenceType && reference.Uri[0] == '#')
				{
					XmlElement signedProperties = document.SelectSingleNode($"//xades:SignedProperties[@Id='{reference.Uri.Substring(1)}']", nsm) as XmlElement;
					if (signedProperties != null)
					{
						_signedProperties = signedProperties;
						_signedPropertiesReference = reference;
						continue;
					}
				}
				// external reference; fix %20 in uri and allow manual resolution to stream
				_xadesFiles.Add(new XadesFile(reference));
			}
			if (_signedProperties == null)
				return;

			// parse signature policy
			_signatureProperties = new XadesSignatureProperties(_signedProperties, nsm);

			// create xades files
			foreach (XadesFile file in _xadesFiles)
				file.ParseProperties(_signedProperties, nsm);
		}

		/// <summary>
		/// Get or set the canonicalization method; use a value from System.Security.Cryptography.Xml.SignedXml
		/// </summary>
		public string CanonicalizationMethod
		{
			get { return _signedXml.SignedInfo.CanonicalizationMethod; }
			set { _signedXml.SignedInfo.CanonicalizationMethod = value; }
		}
		/// <summary>
		/// Get or set the signature method; use a value from System.Security.Cryptography.Xml.SignedXml
		/// </summary>
		public string SignatureMethod
		{
			get { return _signedXml.SignedInfo.SignatureMethod; }
			set { _signedXml.SignedInfo.SignatureMethod = value; }
		}

		/// <summary>
		/// Signature properties (Signature policy)
		/// </summary>
		public XadesSignatureProperties SignatureProperties
		{
			get { return _signatureProperties; }
		}

		/// <summary>
		/// List of files to sign
		/// </summary>
		public List<XadesFile> Files
		{
			get { return _xadesFiles; }
		}

		/// <summary>
		/// Flag indicating whether the XmlDsig <SignedInfo> matched the signature after the last call to CheckSignature
		/// </summary>
		public bool ValidSignedInfo
		{
			get { return _validSignedInfo; }
		}

		/// <summary>
		/// Flag indicating whether the Xades <SignedProperties> hash matched the hash value stored in the corresponding reference after the last call to CheckSignature
		/// </summary>
		public bool ValidSignedProperties
		{
			get { return _validSignedProperties; }
		}

		/// <summary>
		/// Create Xades signature of the included files
		/// </summary>
		/// <param name="certificate"></param>
		/// <param name="resolver"></param>
		/// <returns></returns>
		public Stream CreateSignature(X509Certificate2 certificate, UriResolver resolver = null)
		{
			// create valid ids for all files
			CreateFileIds();

			// build xades XML
			XmlElement signatureProperties = _signatureProperties.CreateXadesSignatureProperties(_document, certificate);
			XmlElement dataObjectProperties = CreateXadesDataObjectProperties(_document);
			XmlElement qualifyingProperties = CreateXadesQualifyingProperties(_document, signatureProperties, dataObjectProperties);
			_document.DocumentElement.AppendChild(qualifyingProperties);

			// add reference to xades XML
			_signedXml.AddObject(new DataObject(null, null, null, qualifyingProperties));
			_signedPropertiesReference = new Reference($"#{XadesSignedPropertiesId}") { TransformChain = _xadesTransformChain, DigestMethod = _xadesDigestMethod, Type = XadesSignature.XadesReferenceType };
			_signedXml.AddReference(_signedPropertiesReference);
			_signedXml.Signature.Id = XadesSignature.XadesSignatureRootId;

			// add reference for each file
			foreach (XadesFile file in _xadesFiles)
				_signedXml.AddReference(file.GetReference(resolver));

			// set key
			KeyInfo keyInfo = new KeyInfo();
			keyInfo.AddClause(new KeyInfoX509Data(certificate));
			_signedXml.SigningKey = certificate.GetRSAPrivateKey();
			_signedXml.KeyInfo = keyInfo;

			// calculate signature
			_signedXml.ComputeSignature();
			XmlElement root = _signedXml.GetXml();

			return new MemoryStream(Encoding.UTF8.GetBytes(root.OuterXml));
		}

		/// <summary>
		/// Create Xades <QualifyingProperties> from the <SignatureProperties> and <DataObjectProperties> elements
		/// </summary>
		/// <param name="document"></param>
		/// <param name="signatureProperties"></param>
		/// <param name="dataObjectProperties"></param>
		/// <returns></returns>
		private XmlElement CreateXadesQualifyingProperties(XmlDocument document, XmlElement signatureProperties, XmlElement dataObjectProperties)
		{
			XmlElement qualifyingProperties = document.CreateElement("QualifyingProperties", XadesSignature.XadesNamespaceUrl);
			qualifyingProperties.SetAttribute("Target", $"#{XadesSignature.XadesSignatureRootId}");
			_signedProperties = qualifyingProperties.CreateChild("SignedProperties", XadesSignature.XadesNamespaceUrl);
			_signedProperties.SetAttribute("Id", XadesSignature.XadesSignedPropertiesId);

			_signedProperties.AppendChild(signatureProperties);
			_signedProperties.AppendChild(dataObjectProperties);

			return qualifyingProperties;
		}

		/// <summary>
		/// Create Xades <DataObjectProperties>
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		private XmlElement CreateXadesDataObjectProperties(XmlDocument document)
		{
			XmlElement dataObjectProperties = document.CreateElement("SignedDataObjectProperties", XadesSignature.XadesNamespaceUrl);
			foreach (XadesFile file in _xadesFiles)
				dataObjectProperties.AppendChild(file.GetObjectFormat(document));
			foreach (XadesFile file in _xadesFiles)
				dataObjectProperties.AppendChild(file.GetCommitmentTypeIndication(document));
			return dataObjectProperties;
		}

		/// <summary>
		/// Create unique ids for any files without
		/// </summary>
		private void CreateFileIds()
		{
			HashSet<string> ids = new HashSet<string>();
			int n = 0;
			foreach (XadesFile file in _xadesFiles)
			{
				if (file.Id == null || ids.Contains(file.Id))
				{
					string id;
					for (; ids.Contains(id = $"xmldsig-ref{n}"); n++) { }
					file.Id = id;
				}
				ids.Add(file.Id);
			}
		}

		/// <summary>
		/// Check Xades signature
		/// </summary>
		/// <param name="resolver"></param>
		/// <returns></returns>
		public bool CheckSignature(UriResolver resolver = null)
		{
			X509Certificate2 certificate;
			return CheckSignature(out certificate, resolver);
		}

		/// <summary>
		/// Check Xades signature
		/// </summary>
		/// <param name="certificate"></param>
		/// <param name="resolver"></param>
		/// <returns></returns>
		public bool CheckSignature(out X509Certificate2 certificate, UriResolver resolver = null)
		{
			// find appropriate public key and verify signature
			MethodInfo checkSignedInfo = typeof(SignedXml).GetMethod("CheckSignedInfo", BindingFlags.NonPublic | BindingFlags.Instance, null, new Type[] { typeof(AsymmetricAlgorithm) }, null);

			// find certificate
			certificate = null;
			_validSignedInfo = false;
			foreach (KeyValuePair<AsymmetricAlgorithm, X509Certificate2> algInfo in GetPublicKeys(_signedXml.KeyInfo))
			{
				if ((bool)checkSignedInfo.Invoke(_signedXml, new object[] { algInfo.Key }))
				{
					_validSignedInfo = true;
					certificate = algInfo.Value;
					break;
				}
			}

			// verify referenced document hashes
			bool validReferences = true;
			foreach (XadesFile file in _xadesFiles)
				validReferences = file.CheckDigest(resolver) && validReferences;

			// verify Xades signed properties
			if (_signedProperties != null)
			{
				XmlDocument document = new XmlDocument() { PreserveWhitespace = true };
				using (TextReader textReader = new StringReader(_signedProperties.OuterXml))
					document.Load(XmlReader.Create(textReader));
				byte[] xadesDigest = XadesUtils.CalculateHash(document, _signedPropertiesReference.TransformChain, _signedPropertiesReference.DigestMethod);
				_validSignedProperties = XadesUtils.DigestEqual(xadesDigest, _signedPropertiesReference.DigestValue);
			}
			else
				_validSignedProperties = false;

			return _validSignedInfo && validReferences && _validSignedProperties;
		}

		/// <summary>
		/// Enumerate all public keys (with their certificate if available) in keyInfo
		/// </summary>
		/// <param name="keyInfo"></param>
		/// <returns></returns>
		private IEnumerable<KeyValuePair<AsymmetricAlgorithm, X509Certificate2>> GetPublicKeys(KeyInfo keyInfo)
		{
			System.Collections.IEnumerator enumerator = keyInfo.GetEnumerator();
			while (enumerator.MoveNext())
			{
				KeyInfoX509Data keyInfoX509Data = enumerator.Current as KeyInfoX509Data;
				if (keyInfoX509Data != null)
					foreach (X509Certificate2 certificate in keyInfoX509Data.Certificates)
					{
						AsymmetricAlgorithm asyncAlg = (AsymmetricAlgorithm)certificate.GetRSAPublicKey() ?? (AsymmetricAlgorithm)certificate.GetDSAPublicKey() ?? (AsymmetricAlgorithm)certificate.GetECDsaPublicKey();
						if (asyncAlg != null)
							yield return new KeyValuePair<AsymmetricAlgorithm, X509Certificate2>(asyncAlg, certificate);
					}

				RSAKeyValue rSAKeyValue = enumerator.Current as RSAKeyValue;
				if (rSAKeyValue != null)
					yield return new KeyValuePair<AsymmetricAlgorithm, X509Certificate2>(rSAKeyValue.Key, null);

				DSAKeyValue dSAKeyValue = enumerator.Current as DSAKeyValue;
				if (dSAKeyValue != null)
					yield return new KeyValuePair<AsymmetricAlgorithm, X509Certificate2>(dSAKeyValue.Key, null);
			}
		}
	}
}
