using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Windows;

namespace SBRAssurance
{
	public static class Utils
	{
		/// <summary>
		/// List all certificate with a private key and usage non-repudiation
		/// </summary>
		/// <returns></returns>
		public static X509Certificate2Collection GetCertificates()
		{
			using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
			{
				store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
				X509Certificate2Collection collection = store.Certificates.Find(X509FindType.FindByKeyUsage, X509KeyUsageFlags.NonRepudiation, true);
				for (int i = collection.Count - 1; i >= 0; i--)
					if (!collection[i].HasPrivateKey)
						collection.RemoveAt(i);
				return collection;
			}
		}
	}

	public static class Extensions
	{
		public static Stream OpenRead(this Uri uri)
		{
			if (uri.IsFile)
			{
				if (!String.IsNullOrEmpty(uri.Fragment) && uri.GetComponents(UriComponents.Path, UriFormat.Unescaped).EndsWith(".zip", StringComparison.InvariantCultureIgnoreCase))
				{
					ZipArchive zip = ZipFile.OpenRead(uri.LocalPath);
					return zip.GetEntry(uri.GetComponents(UriComponents.Fragment, UriFormat.Unescaped))?.Open();
				}
				else
					return File.OpenRead(uri.LocalPath);
			}
			else
			{
				WebClient wc = new WebClient();
				return wc.OpenRead(uri);
			}
		}

		public static IEnumerable<string> GetFiles(this DragEventArgs e)
		{
			if (e.Data != null)
			{
				string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
				if (files != null)
				{
					foreach (string file in files)
						yield return file;
					yield break;
				}
				string uri = e.Data.GetData(DataFormats.StringFormat) as string;
				if (uri != null)
					yield return uri;
			}
		}
	}
}
