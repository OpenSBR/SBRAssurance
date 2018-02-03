using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Xml;

namespace SBRAssurance.Model
{
	public enum FileType
	{
		Signature,
		XBRLInstance,
		XBRLLinkbase,
		XMLSchema,
		XML,
		Unknown,
		NotFound
	}

	public class FileEntry : INotifyPropertyChanged
	{
		/// <summary>
		/// Create file entry and auto-detect file type
		/// </summary>
		/// <param name="uri"></param>
		/// <param name="stream"></param>
		public FileEntry(Uri uri, Stream stream = null)
		{
			Uri = uri;

			Name = String.IsNullOrEmpty(uri.Fragment) ? Path.GetFileName(uri.GetComponents(UriComponents.Path, UriFormat.Unescaped)) : uri.GetComponents(UriComponents.Fragment, UriFormat.Unescaped);

			if (stream == null)
			{
				stream = uri.OpenRead();
				if (stream == null)
					throw new FileNotFoundException("File not found");
			}

			// detect file type
			Type = FileType.Unknown;
			XmlDocument document = new XmlDocument();
			try
			{
				document.Load(stream);
				XmlElement root = document.DocumentElement;
				if (root.LocalName == "Signature" && root.NamespaceURI == System.Security.Cryptography.Xml.SignedXml.XmlDsigNamespaceUrl)
					Type = FileType.Signature;
				else if (root.LocalName == "schema" && root.NamespaceURI == "http://www.w3.org/2001/XMLSchema")
					Type = FileType.XMLSchema;
				else if (root.LocalName == "linkbase" && root.NamespaceURI == "http://www.xbrl.org/2003/linkbase")
					Type = FileType.XBRLLinkbase;
				else if (root.LocalName == "xbrl" && root.NamespaceURI == "http://www.xbrl.org/2003/instance")
					Type = FileType.XBRLInstance;
				else
					Type = FileType.XML;
			}
			catch (Exception)
			{ }
		}

		public Uri Uri { get; private set; }
		public string Name { get; private set; }
		public FileType Type { get; private set; }
		// String representation of type enum
		public string TypeStr
		{
			get { return System.Text.RegularExpressions.Regex.Replace(Type.ToString(), @"(\w)([A-Z][^A-Z])", "$1 $2"); }
		}

		public CommitmentType CommitmentType { get; set; }
		public TransformSet TransformSet { get; set; }

		#region Signature check specific part
		/// <summary>
		/// Create dummy file entry
		/// </summary>
		/// <param name="name"></param>
		public FileEntry(string name)
		{
			Name = name;
			Type = FileType.NotFound;
		}

		// Raw commitment type string (check)
		private string _commitmentTypeId;
		public string CommitmentTypeId
		{
			get { return _commitmentTypeId; }
			set
			{
				_commitmentTypeId = value;
				NotifyChange();
			}
		}
		private bool? _isValid;
		public bool? IsValid
		{
			get { return _isValid; }
			set
			{
				_isValid = value;
				NotifyChange();
			}
		}
		#endregion

		#region INotifyPropertyChanged

		public event PropertyChangedEventHandler PropertyChanged;
		protected void NotifyChange([CallerMemberName] string property = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
		}
		#endregion
	}
}
