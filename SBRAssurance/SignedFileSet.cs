using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;

namespace SBRAssurance
{
	public abstract class SignedFileSet : IDisposable
	{
		public virtual void Dispose()
		{ }

		public virtual void AddFile(string name, Uri uri)
		{ }

		public virtual void AddFile(string name, Stream stream)
		{ }

		public virtual void Close()
		{ }

		public virtual void Abort()
		{ }
	}

	public class SignedSetPath : SignedFileSet
	{
		private string _path;
		private List<string> _fileList;

		public SignedSetPath(string path)
		{
			_path = path;
			_fileList = new List<string>();
		}

		public override void AddFile(string name, Uri uri)
		{
			string file = Path.Combine(_path, name);
			if (uri.IsFile && uri.LocalPath == file)
				return;
			using (Stream stream = uri.OpenRead())
				Copy(stream, file);
		}

		public override void AddFile(string name, Stream stream)
		{
			string file = Path.Combine(_path, name);
			// C# 7.0 syntax
			if (stream is FileStream srcStream && Path.GetFullPath(srcStream.Name) == file)
				return;
			Copy(stream, file);
		}

		private void Copy(Stream stream, string file)
		{
			using (Stream dstStream = File.OpenWrite(file))
				stream.CopyTo(dstStream);
			_fileList.Add(file);
		}

		public override void Abort()
		{
			foreach (string file in _fileList)
				File.Delete(file);
		}
	}

	public class SignedSetZip : SignedFileSet
	{
		private string _zipFile;
		private ZipArchive _zip;

		public SignedSetZip(string zipFile)
		{
			if (File.Exists(zipFile))
				File.Delete(zipFile);
			_zipFile = zipFile;
			_zip = ZipFile.Open(zipFile, ZipArchiveMode.Create);
		}

		public override void Dispose()
		{
			_zip.Dispose();
		}

		public override void AddFile(string name, Uri uri)
		{
			using (Stream stream = uri.OpenRead())
				AddFile(name, stream);
		}

		public override void AddFile(string name, Stream stream)
		{
			ZipArchiveEntry zipEntry = _zip.CreateEntry(name, CompressionLevel.Optimal);
			using (Stream zipStream = zipEntry.Open())
				stream.CopyTo(zipStream);
		}

		public override void Close()
		{
			_zip.Dispose();
		}

		public override void Abort()
		{
			_zip.Dispose();
			File.Delete(_zipFile);
		}
	}
}
