using Microsoft.Win32;
using OpenSBR.Xades;
using SBRAssurance.Model;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;

namespace SBRAssurance
{
	/// <summary>
	/// Interaction logic for MainWindow.xaml
	/// </summary>
	public partial class MainWindow : Window, INotifyPropertyChanged
	{
		public MainWindow()
		{
			InitializeComponent();

			// Initialize for proper parsing of the transform chains in settings
			XadesSignature.Init();
			Settings = Settings.Load();

			// read policies
			Policies = new ObservableCollection<SignPolicy>();
			foreach (string url in Settings.PolicyURLs)
				Policies.Add(new SignPolicy(url, Settings.PreferredLanguage));
			Files = new ObservableCollection<FileEntry>();
			CertificateList = new ObservableCollection<X509Certificate2>(Utils.GetCertificates().OfType<X509Certificate2>());

			// set defaults
			SelectedPolicy = Policies.FirstOrDefault();
			SelectedCertificate = CertificateList.FirstOrDefault();

			SaveAsZip = true;

			_lastDirectory = Environment.CurrentDirectory;

			DataContext = this;
		}

		private string _lastDirectory;
		public Settings Settings { get; set; }

		public ObservableCollection<SignPolicy> Policies { get; private set; }
		private SignPolicy _selectedPolicy;
		public SignPolicy SelectedPolicy
		{
			get { return _selectedPolicy; }
			set
			{
				_selectedPolicy = value;
				NotifyChange();
			}
		}

		public ObservableCollection<FileEntry> Files { get; private set; }
		public ObservableCollection<X509Certificate2> CertificateList { get; private set; }
		public X509Certificate2 SelectedCertificate { get; set; }

		public bool SaveAsZip { get; set; }

		// Enable signature creation only if files in list, with commitment ype set and none of type signature or unknown
		public bool SignEnable
		{
			get { return Files.Count > 0 && !Files.Any(x => x.Type == FileType.Signature || x.Type == FileType.NotFound) && !Files.Any(x => x.CommitmentType == null); }
		}

		// Enable choices only if no signature in file list
		//  otherwise show check marks
		#region Visibility flags for mode switch
		private bool _inCheckingMode;
		public Visibility CheckItemVisibility
		{
			get { return _inCheckingMode ? Visibility.Visible : Visibility.Collapsed; }
		}
		public Visibility SignItemVisibility
		{
			get { return _inCheckingMode ? Visibility.Collapsed : Visibility.Visible; }
		}
		#endregion

		// states for signature check
		#region Signature check results
		private bool _signatureIsValid;
		private string _signPolicy;
		private bool? _signPolicyIsValid;
		private X509Certificate2 _signCert;
		private bool? _signCertIsValid;
		private X509Certificate2 _signCACert;
		private string _signCertError;

		public bool SignatureIsValid
		{
			get { return _signatureIsValid; }
			set { _signatureIsValid = value; NotifyChange(); }
		}
		public string SignPolicy
		{
			get { return _signPolicy; }
			set { _signPolicy = value; NotifyChange(); }
		}
		public bool? SignPolicyIsValid
		{
			get { return _signPolicyIsValid; }
			set { _signPolicyIsValid = value; NotifyChange(); }
		}
		public X509Certificate2 SignCert
		{
			get { return _signCert; }
			private set { _signCert = value; NotifyChange(); }
		}
		public bool? SignCertIsValid
		{
			get { return _signCertIsValid; }
			set { _signCertIsValid = value; NotifyChange(); }
		}
		public X509Certificate2 SignCACert
		{
			get { return _signCACert; }
			private set { _signCACert = value; NotifyChange(); }
		}
		public string SignCertError
		{
			get { return _signCertError; }
			private set { _signCertError = value; NotifyChange(); }
		}
		#endregion

		private void About_Click(object sender, RoutedEventArgs e)
		{
			About.Show(this);
		}

		private void AddFiles_Click(object sender, RoutedEventArgs e)
		{
			OpenFileDialog ofd = new OpenFileDialog();
			ofd.InitialDirectory = _lastDirectory;
			ofd.Multiselect = true;
			ofd.Filter = "XBRL/XML files|*.xbrl;*.xml|XML schemas (XSD)|*.xsd|All files|*.*";
			if (ofd.ShowDialog() != true)
				return;
			_lastDirectory = Path.GetDirectoryName(ofd.FileName);
			AddFileList(ofd.FileNames);
		}

		// drop handler
		private void Window_Drop(object sender, DragEventArgs e)
		{
			AddFileList(e.GetFiles());
		}

		private void AddFileList(IEnumerable<string> files)
		{
			foreach (string file in files)
			{
				// create uri; ignore unresolvable (in this case - all relative uris)
				Uri uri = new Uri(file, UriKind.RelativeOrAbsolute);
				if (!uri.IsAbsoluteUri)
					continue;

				if (uri.IsFile && uri.LocalPath.EndsWith(".zip", StringComparison.InvariantCultureIgnoreCase))
				{
					// if uri points to a local zip, add the contents instead
					using (ZipArchive zip = ZipFile.OpenRead(uri.LocalPath))
						foreach (ZipArchiveEntry entry in zip.Entries)
						{
							UriBuilder ub = new UriBuilder(uri);
							ub.Fragment = entry.FullName;
							AddFile(new FileEntry(ub.Uri, entry.Open()));
						}
				}
				else if (uri.IsFile && File.GetAttributes(uri.LocalPath).HasFlag(FileAttributes.Directory))
				{
					// if uri points to a directory, add the contents instead (notes: does not recurse into subdirectories)
					AddFileList(Directory.GetFiles(uri.LocalPath));
				}
				else
					AddFile(new FileEntry(uri));
			}
			NotifyChange("SignEnable");

			UpdateViewState();
		}

		// add file, remove duplicate names, replace signature
		private void AddFile(FileEntry fe)
		{
			for (int i = Files.Count - 1; i >= 0; i--)
				if (Files[i].Name == fe.Name)
					Files.RemoveAt(i);
			if (fe.Type == FileType.Signature)
			{
				for (int i = Files.Count - 1; i >= 0; i--)
					if (Files[i].Type == FileType.Signature)
						Files.RemoveAt(i);
			}
			// determine default transform set
			fe.TransformSet = Settings.TransformSets.FirstOrDefault(x => x.DefaultFor != null && x.DefaultFor.Contains(fe.Type.ToString())) ?? Settings.TransformSets.FirstOrDefault();
			Files.Add(fe);
		}

		private void RemoveItem_Click(object sender, RoutedEventArgs e)
		{
			FileEntry fe = (sender as Button)?.DataContext as FileEntry;
			Files.Remove(fe);
			NotifyChange("SignEnable");

			UpdateViewState();
		}

		// re-evaluate sign state after policy selection changed
		private void CommitmentType_SelectionChanged(object sender, SelectionChangedEventArgs e)
		{
			NotifyChange("SignEnable");
		}

		// create signature
		private void Sign_Click(object sender, RoutedEventArgs e)
		{
			if (!SignEnable)
				return;

			// select certificate
			X509Certificate2 cert = SelectedCertificate;
			if (cert == null)
			{
				X509Certificate2Collection certs = X509Certificate2UI.SelectFromCollection(Utils.GetCertificates(), "Select a certificate", "Choose your certifcate to sign documents and provide proof of integrity", X509SelectionFlag.SingleSelection);
				if (certs.Count < 1)
					return;
				cert = certs[0];
			}
			if (cert == null)
				return;

			// select folder or zip file
			SignedFileSet signedSet;
			SaveFileDialog sfd = new SaveFileDialog();
			sfd.InitialDirectory = _lastDirectory;
			if (SaveAsZip)
			{
				sfd.FileName = $"Signature-{DateTime.Now.ToString("yyMMdd")}";
				sfd.Filter = "Zip files|*.zip|All files|*.*";
				if (sfd.ShowDialog() != true)
					return;
				signedSet = new SignedSetZip(sfd.FileName);
			}
			else
			{
				sfd.FileName = "[Select Folder]";
				sfd.Filter = "Folders|\\";
				sfd.OverwritePrompt = false;
				if (sfd.ShowDialog() != true)
					return;
				signedSet = new SignedSetPath(Path.GetDirectoryName(sfd.FileName));
			}
			_lastDirectory = Path.GetDirectoryName(sfd.FileName);

			Cursor lastCursor = Cursor;
			Cursor = Cursors.Wait;

			try
			{
				// create signature
				//
				XadesSignature xadesSignature = new XadesSignature();
				// set signature policy
				xadesSignature.SignatureProperties.PolicyId = SelectedPolicy.Id;
				xadesSignature.SignatureProperties.PolicyTransformChain = SelectedPolicy.TransformChain;
				xadesSignature.SignatureProperties.PolicyDigestMethod = SelectedPolicy.PolicyDigest;
				xadesSignature.SignatureProperties.UpdateHash(SelectedPolicy.URL);

				// set signature method
				xadesSignature.CanonicalizationMethod = SignedXml.XmlDsigC14NWithCommentsTransformUrl;
				xadesSignature.SignatureMethod = SignedXml.XmlDsigRSASHA256Url;		// should check if allowed in policy

				// prepare and add file descriptors
				foreach (FileEntry file in Files)
				{
					TransformChain chain = file.TransformSet?.TransformChain;
					XadesFile xadesFile = new XadesFile(file.Name, chain, SignedXml.XmlDsigSHA256Url);
					xadesFile.CommitmentTypeId = file.CommitmentType.Id;
					xadesSignature.Files.Add(xadesFile);

					// copy file to output directory/zip
					signedSet.AddFile(file.Name, file.Uri);
				}

				// create signature
				using (Stream signatureStream = xadesSignature.CreateSignature(cert, ResolveUri))
					signedSet.AddFile("signature.xml", signatureStream);
				// close file set (triggers copying files to destination or close zip file)
				signedSet.Close();
			}
			catch (System.Security.Cryptography.CryptographicException ce)
			{
				// Cryptographic exceptions can be thrown when the certificate is not valid or the proper password / other security measures were not supplied
				signedSet.Abort();
				MessageBox.Show(this, $"Failed to create signature:\r\n{ce.Message}", "Error");
			}
			catch (Exception ex)
			{
				signedSet.Abort();
				MessageBox.Show(this, $"An error occured:\r\n\r\n{ex.GetType()}: {ex.Message}", "Error");
			}

			Cursor = lastCursor;
		}

		/// <summary>
		/// Set view to signing or checking mode
		/// </summary>
		private void UpdateViewState()
		{
			Cursor lastCursor = Cursor;
			Cursor = Cursors.Wait;

			// Set check view if signature present in file list; otherwise sign view
			IEnumerable<FileEntry> signatureFiles = Files.Where(x => x.Type == FileType.Signature);
			_inCheckingMode = signatureFiles.Count() == 1;
			NotifyChange("SignItemVisibility");
			NotifyChange("CheckItemVisibility");

			if (_inCheckingMode)
			{
				try
				{
					// check signature
					XadesSignature signature = new XadesSignature(signatureFiles.First().Uri.OpenRead());
					X509Certificate2 certificate;
					SignatureIsValid = signature.CheckSignature(out certificate, ResolveUri);

					// check signature properties (if present)
					if (signature.SignatureProperties != null)
					{
						SignPolicy policy = Policies.SingleOrDefault(x => x.Id == signature.SignatureProperties.PolicyId);
						SignPolicy = signature.SignatureProperties.PolicyId;
						SignPolicyIsValid = policy != null && signature.SignatureProperties.CheckDigest(policy.URL);
					}
					else
						SignPolicyIsValid = false;

					// update flags in file list and add entries for missing files
					foreach (XadesFile xadesFile in signature.Files)
					{
						FileEntry fe = Files.SingleOrDefault(x => x.Name == xadesFile.URI);
						if (fe == null)
						{
							fe = new FileEntry(xadesFile.URI);
							Files.Add(fe);
						}
						fe.CommitmentTypeId = xadesFile.CommitmentTypeId;
						fe.IsValid = xadesFile.IsValid;
					}
					// set state for signature file
					foreach (FileEntry fe in Files.Where(x => !signature.Files.Any(y => y.URI == x.Name)))
						fe.IsValid = fe.Type == FileType.Signature ? (bool?)(signature.ValidSignedInfo && signature.ValidSignedProperties) : null;

					// check certificate
					SignCert = certificate;
					if (certificate != null)
					{
						X509Chain chain = new X509Chain();
						chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
						//chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
						SignCertIsValid = chain.Build(certificate);
						SignCertError = (SignCertIsValid == false) ? chain.ChainStatus?.First().StatusInformation.Trim() : null;
						SignCACert = chain.ChainElements.OfType<X509ChainElement>().LastOrDefault(x => x.Certificate.Extensions.OfType<X509BasicConstraintsExtension>().Any(y => y.CertificateAuthority))?.Certificate;
					}
					else
					{
						SignCertIsValid = null;
						SignCACert = null;
						SignCertError = null;
					}
				}
				catch (Exception)
				{
					SignatureIsValid = false;
					SignPolicy = null;
					SignPolicyIsValid = null;
					SignCertIsValid = null;
					SignCACert = null;
					SignCertError = null;
					foreach (FileEntry fe in Files)
						fe.IsValid = null;

					MessageBox.Show(this, "Invalid signature file format", "Error");
				}
			}
			else
			{
				// remove files that don't exist
				for (int i = Files.Count - 1; i >= 0; i--)
					if (Files[i].Uri == null)
						Files.RemoveAt(i);
			}
			Cursor = lastCursor;
		}

		private Stream ResolveUri(string uri)
		{
			FileEntry fe = Files.SingleOrDefault(x => x.Name == uri);
			return fe?.Uri?.OpenRead();
		}

		#region INotifyPropertyChanged

		public event PropertyChangedEventHandler PropertyChanged;
		protected void NotifyChange([CallerMemberName] string property = null)
		{
			PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(property));
		}
		#endregion
	}
}
