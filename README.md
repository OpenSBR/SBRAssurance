Current version: 1.0
# Introduction
Standard Business Reporting is a Dutch program, which applies technical and semantical standards to reduce the administrative burden for businesses.
Key components of SBR are the reporting standard XBRL, system-to-system filing and a public-private partnership.

To be able to provide assurance on annual reports, the standard SBR Assurance was created. SBR Assurance specifies a detached signature, based on C14N and XAdES to be able to verify the origin and authenticity of annual reports and assurance reports.

This GIT contains a library for the creation and verification of detached signature with a digital PKI certificate.

# Getting Started
This .NET solution contains the following projects:
1. A library for the creation and verification of detached signatures
2. A simple user interface for the creation and verification of detached signatures.

# Build and Test
The library can be used as a standard .NET project.

The user interface can be built and run as a desktop tool.

Only certificates issued by a valid trusted root can be selected to create a signature. Test signing is still possible by creating a self-signed certificate chain. Since this involves adding a certificate to the trusted root certificate store, extensive knowledge on the subject is advised.
The requirements for these test certificates are:
- A self-signed root certificate, placed in the "Trusted Root Certification Authorities" store of the current user
- A document signing certificate, created with the aforementioned root certificate, placed in the "Personal" store with:
  - "Non-Repudiation" included in key usage
  - RSA-SHA256 signature algorithm

The Microsoft utility CertReq can be used to create both certificates.

# Limitations
The user interface should be considered a proof of concept and has minimal error handling. It has been made to support v1.0 of the Dutch SBR signature policy specifically and some assumptions have been made based on this.

This project has a number of limitations and architecture choices:
- .NET 4.6.2; this is required for support of RSA-SHA256 in XML signing
- .NET limitations:
  - The XMLDSig filter transform implemented in the library is built on default .NET components and therefore limited to XPath 1.0
  - Certain XPath filters result in incorrect output due to a bug in the .NET framework; a workaround is included in the library

Limitations and assumptions specific to the user interface:
- Fixed signature algorithm of RSA-SHA256
- Fixed hash algorithm of SHA256

# Contribute
OpenSBR encourages coders, enthousiasts and software vendors to contribute to the OpenSBR project. We appreciate improvements to code, extensions, new projects and functionality and other contributions.
Check [http://opensbr.org/](http://opensbr.org/) for more information on how to contribute.
