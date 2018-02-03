using System;
using System.IO;
using System.Net;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace OpenSBR.Xades
{
	public class XadesFile
	{
		private string _uri;

		private TransformChain _transformChain;
		private string _digestMethod;
		private Reference _reference;

		private string _id;

		private string _description;
		private string _identifier;
		private string _mimeType;
		private string _encoding;

		private string _commitmentTypeId;

		private bool _isValid;

		/// <summary>
		/// Create new document reference
		/// </summary>
		/// <param name="uri"></param>
		/// <param name="transformChain"></param>
		/// <param name="digestMethod"></param>
		public XadesFile(string uri, TransformChain transformChain, string digestMethod)
		{
			_uri = uri;
			_transformChain = transformChain;
			_digestMethod = SignedXml.XmlDsigSHA256Url;
		}

		/// <summary>
		/// Create new instance from Reference (from existing document)
		/// </summary>
		/// <param name="reference"></param>
		internal XadesFile(Reference reference)
		{
			_uri = Uri.UnescapeDataString(reference.Uri);
			_transformChain = reference.TransformChain;
			_digestMethod = reference.DigestMethod;
			_id = reference.Id;
			_reference = reference;
		}

		public string Id
		{
			get { return _id; }
			set { _id = value; }
		}

		public string URI
		{
			get { return _uri; }
			set { _uri = value; }
		}

		public string Description
		{
			get { return _description; }
			set { _description = value; }
		}

		public string Identifier
		{
			get { return _identifier; }
			set { _identifier = value; }
		}

		public string MimeType
		{
			get { return _mimeType; }
			set { _mimeType = value; }
		}

		public string Encoding
		{
			get { return _encoding; }
			set { _encoding = value; }
		}

		public string CommitmentTypeId
		{
			get { return _commitmentTypeId; }
			set { _commitmentTypeId = value; }
		}

		public bool IsValid
		{
			get { return _isValid; }
		}

		/// <summary>
		/// Create Reference for this document
		/// </summary>
		/// <param name="resolver"></param>
		/// <returns></returns>
		internal Reference GetReference(XadesSignature.UriResolver resolver = null)
		{
			Stream stream = (resolver != null) ? resolver(_uri) : null;
			Reference reference = (stream != null) ? new Reference(stream) : new Reference(_uri);

			reference.Uri = Uri.EscapeDataString(_uri);
			reference.TransformChain = _transformChain;
			reference.DigestMethod = _digestMethod ?? SignedXml.XmlDsigSHA256Url;
			reference.Id = _id;

			_reference = reference;
			return reference;
		}

		/// <summary>
		/// Create <DataObjectFormat> for this document
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		internal XmlElement GetObjectFormat(XmlDocument document)
		{

			XmlElement objectFormat = document.CreateElement("DataObjectFormat", XadesSignature.XadesNamespaceUrl);
			objectFormat.SetAttribute("ObjectReference", $"#{_id}");

			if (_description != null || (_identifier == null && _mimeType == null))
			{
				XmlElement description = objectFormat.CreateChild("Description", XadesSignature.XadesNamespaceUrl);
				description.InnerText = _description ?? _uri;
			}

			if (_identifier != null)
			{
				XmlElement objectIdentifier = objectFormat.CreateChild("ObjectIdentifier", XadesSignature.XadesNamespaceUrl);
				XmlElement identifier = objectIdentifier.CreateChild("Identifier", XadesSignature.XadesNamespaceUrl);
				identifier.InnerText = _identifier;
			}

			if (_mimeType != null)
			{
				XmlElement mimeType = objectFormat.CreateChild("MimeType", XadesSignature.XadesNamespaceUrl);
				mimeType.InnerText = _mimeType;
			}
			if (_encoding != null)
			{
				XmlElement encoding = objectFormat.CreateChild("Encoding", XadesSignature.XadesNamespaceUrl);
				encoding.InnerText = _encoding;
			}

			return objectFormat;
		}

		/// <summary>
		/// Create <CommitmentTypeIndication> for this document
		/// </summary>
		/// <param name="document"></param>
		/// <returns></returns>
		internal XmlElement GetCommitmentTypeIndication(XmlDocument document)
		{
			XmlElement commitmentTypeIndication = document.CreateElement("CommitmentTypeIndication", XadesSignature.XadesNamespaceUrl);
			XmlElement typeId = commitmentTypeIndication.CreateChild("CommitmentTypeId", XadesSignature.XadesNamespaceUrl);
			XmlElement identifier = typeId.CreateChild("Identifier", XadesSignature.XadesNamespaceUrl);
			identifier.InnerText = _commitmentTypeId;
			XmlElement objectReference = commitmentTypeIndication.CreateChild("ObjectReference", XadesSignature.XadesNamespaceUrl);
			objectReference.InnerText = $"#{_id}";

			return commitmentTypeIndication;
		}

		/// <summary>
		/// Parse the DataObjectFormat and CommitmentTypeIndication properties for this document id
		/// </summary>
		/// <param name="element"></param>
		/// <param name="nsm"></param>
		internal void ParseProperties(XmlElement element, XmlNamespaceManager nsm)
		{
			// data object format
			XmlElement objectFormat = element.SelectSingleNode($"xades:SignedDataObjectProperties/xades:DataObjectFormat[@ObjectReference='#{_id}']", nsm) as XmlElement;

			_description = objectFormat.GetInnerText("xades:Description", nsm);

			_identifier = objectFormat.GetInnerText("xades:ObjectIdentifier/xades:Identifier", nsm);

			_mimeType = objectFormat.GetInnerText("xades:MimeType", nsm);
			_encoding = objectFormat.GetInnerText("xades:Encoding", nsm);

			// commitment type indication
			XmlElement commitmentTypeIndication = element.SelectSingleNode($"xades:SignedDataObjectProperties/xades:CommitmentTypeIndication[xades:ObjectReference='#{_id}']", nsm) as XmlElement;

			_commitmentTypeId = commitmentTypeIndication.GetInnerText("xades:CommitmentTypeId/xades:Identifier", nsm);
		}

		/// <summary>
		/// Calculate the hash of the document and compare with the stored value
		/// </summary>
		/// <param name="resolver"></param>
		/// <returns></returns>
		internal bool CheckDigest(XadesSignature.UriResolver resolver)
		{
			try
			{
				Stream stream;
				if (resolver != null)
					stream = resolver(_uri);
				else
					using (WebClient wc = new WebClient())
						stream = wc.OpenRead(_uri);

				byte[] digest = XadesUtils.CalculateHash(stream, _transformChain, _digestMethod);
				_isValid = XadesUtils.DigestEqual(digest, _reference.DigestValue);
			}
			catch (Exception)
			{
				_isValid = false;
			}
			return _isValid;
		}
	}
}
