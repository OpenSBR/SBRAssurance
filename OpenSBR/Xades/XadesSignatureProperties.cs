using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenSBR.Xades
{
	public class XadesSignatureProperties
	{
		private DateTime _signingTime;

		private string _policyId;
		private TransformChain _policyTransformChain;
		private string _policyDigestMethod;
		private byte[] _policyDigest;

		internal XadesSignatureProperties()
		{ }

		/// <summary>
		/// Create signature properties from existing document
		/// </summary>
		/// <param name="element"></param>
		/// <param name="nsm"></param>
		internal XadesSignatureProperties(XmlElement element, XmlNamespaceManager nsm)
		{
			// read from xml

			// signing time
			XmlElement signingTime = element.SelectSingleNode("xades:SignedSignatureProperties/xades:SigningTime", nsm) as XmlElement;
			if (signingTime != null)
				DateTime.TryParse(signingTime.InnerText, out _signingTime);

			// signing certificate
			foreach (XmlElement cert in element.SelectNodes("xades:SignedSignatureProperties/xades:SigningCertificate/xades:Cert", nsm))
			{
				// TODO: read certificate information and expose as public read-only array
			}

			// signature policy
			XmlElement signaturePolicyId = element.SelectSingleNode("xades:SignedSignatureProperties/xades:SignaturePolicyIdentifier/xades:SignaturePolicyId", nsm) as XmlElement;
			if (signaturePolicyId != null)
			{
				_policyId = signaturePolicyId.GetInnerText("xades:SigPolicyId/xades:Identifier", nsm);

				XmlElement transformChain = signaturePolicyId.SelectSingleNode("ds:Transforms", nsm) as XmlElement;
				if (transformChain != null)
				{
					_policyTransformChain = new TransformChain();
					MethodInfo loadXmlInfo = typeof(TransformChain).GetMethod("LoadXml", BindingFlags.NonPublic | BindingFlags.Instance);
					loadXmlInfo.Invoke(_policyTransformChain, new object[] { transformChain });
				}

				XmlElement policyDigestMethod = signaturePolicyId.SelectSingleNode("xades:SigPolicyHash/ds:DigestMethod", nsm) as XmlElement;
				_policyDigestMethod = policyDigestMethod?.GetAttribute("Algorithm");

				string base64Hash = signaturePolicyId.GetInnerText("xades:SigPolicyHash/ds:DigestValue", nsm);
				_policyDigest = base64Hash != null ? Convert.FromBase64String(base64Hash) : null;
			}
		}

		public DateTime SigningTime
		{
			get { return _signingTime; }
			set { _signingTime = value; }
		}

		public string PolicyId
		{
			get { return _policyId; }
			set { _policyId = value; }
		}

		public TransformChain PolicyTransformChain
		{
			get { return _policyTransformChain; }
			set { _policyTransformChain = value; }
		}

		public string PolicyDigestMethod
		{
			get { return _policyDigestMethod; }
			set { _policyDigestMethod = value; }
		}

		public byte[] PolicyDigest
		{
			get { return _policyDigest; }
			set { _policyDigest = value; }
		}

		/// <summary>
		/// Update hash value from stream
		/// </summary>
		/// <param name="stream"></param>
		public void UpdateHash(Stream stream)
		{
			_policyDigest = XadesUtils.CalculateHash(stream, _policyTransformChain, _policyDigestMethod);
		}

		/// <summary>
		/// Update hash value from document at URI
		/// </summary>
		/// <param name="uri"></param>
		public void UpdateHash(string uri)
		{
			using (WebClient wc = new WebClient())
				using (Stream stream = wc.OpenRead(uri))
					UpdateHash(stream);
		}

		/// <summary>
		/// Create <SignedSignatureProperties>
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		internal XmlElement CreateXadesSignatureProperties(XmlDocument document, X509Certificate2 certificate)
		{
			XmlElement signatureProperties = document.CreateElement("SignedSignatureProperties", XadesSignature.XadesNamespaceUrl);

			// signing time
			if (_signingTime.Ticks == 0)
				_signingTime = DateTime.Now;
			XmlElement signingTime = signatureProperties.CreateChild("SigningTime", XadesSignature.XadesNamespaceUrl);
			signingTime.InnerText = _signingTime.ToString("s");

			// signing certificate
			XmlElement signingCertificate = signatureProperties.CreateChild("SigningCertificate", XadesSignature.XadesNamespaceUrl);
			XmlElement signingCert = signingCertificate.CreateChild("Cert", XadesSignature.XadesNamespaceUrl);
			// certificate digest
			XmlElement certDigest = signingCert.CreateChild("CertDigest", XadesSignature.XadesNamespaceUrl);
			XmlElement certDigestMethod = certDigest.CreateChild("DigestMethod", SignedXml.XmlDsigNamespaceUrl);
			certDigestMethod.SetAttribute("Algorithm", SignedXml.XmlDsigSHA256Url);
			XmlElement certDigestValue = certDigest.CreateChild("DigestValue", SignedXml.XmlDsigNamespaceUrl);
			using (SHA256 sha = SHA256.Create())
				certDigestValue.InnerText = Convert.ToBase64String(sha.ComputeHash(certificate.RawData));
			// certificate issuer
			XmlElement issuerSerial = signingCert.CreateChild("IssuerSerial", XadesSignature.XadesNamespaceUrl);
			XmlElement issuerName = issuerSerial.CreateChild("X509IssuerName", SignedXml.XmlDsigNamespaceUrl);
			issuerName.InnerText = certificate.Issuer;
			XmlElement serial = issuerSerial.CreateChild("X509SerialNumber", SignedXml.XmlDsigNamespaceUrl);
			serial.InnerText = XadesUtils.ToDecimal(XadesUtils.HexToBytes(certificate.SerialNumber));

			// signature policy
			XmlElement signaturePolicyIdentifier = signatureProperties.CreateChild("SignaturePolicyIdentifier", XadesSignature.XadesNamespaceUrl);
			XmlElement signaturePolicyId = signaturePolicyIdentifier.CreateChild("SignaturePolicyId", XadesSignature.XadesNamespaceUrl);

			XmlElement sigPolicyId = signaturePolicyId.CreateChild("SigPolicyId", XadesSignature.XadesNamespaceUrl);
			XmlElement sigPolicyIdIdentifier = sigPolicyId.CreateChild("Identifier", XadesSignature.XadesNamespaceUrl);
			sigPolicyIdIdentifier.InnerText = _policyId;

			if (_policyTransformChain != null && _policyTransformChain.Count > 0)
			{
				MethodInfo getXmlInfo = typeof(TransformChain).GetMethod("GetXml", BindingFlags.NonPublic | BindingFlags.Instance);
				signaturePolicyId.AppendChild((XmlElement)getXmlInfo.Invoke(_policyTransformChain, new object[] { document, SignedXml.XmlDsigNamespaceUrl }));
			}

			if (_policyDigest == null)
				UpdateHash(_policyId);

			XmlElement sigPolicyHash = signaturePolicyId.CreateChild("SigPolicyHash", XadesSignature.XadesNamespaceUrl);
			XmlElement digestMethod = sigPolicyHash.CreateChild("DigestMethod", SignedXml.XmlDsigNamespaceUrl);
			digestMethod.SetAttribute("Algorithm", _policyDigestMethod);
			XmlElement digestValue = sigPolicyHash.CreateChild("DigestValue", SignedXml.XmlDsigNamespaceUrl);
			digestValue.InnerText = Convert.ToBase64String(_policyDigest);

			return signatureProperties;
		}

		/// <summary>
		/// Check signature policy hash
		/// </summary>
		/// <param name="stream"></param>
		/// <returns></returns>
		public bool CheckDigest(Stream stream)
		{
			byte[] digest = XadesUtils.CalculateHash(stream, _policyTransformChain, _policyDigestMethod);
			return XadesUtils.DigestEqual(digest, _policyDigest);
		}

		/// <summary>
		/// Check signature policy hash
		/// </summary>
		/// <param name="uri"></param>
		/// <returns></returns>
		public bool CheckDigest(string uri = null)
		{
			using (WebClient wc = new WebClient())
				using (Stream stream = wc.OpenRead(uri ?? _policyId))
					return CheckDigest(stream);
		}
	}
}
