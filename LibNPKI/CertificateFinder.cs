using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using Mono.Security.Cryptography;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto.Engines;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace LibNPKI
{
    public class CertificateFinder
    {
        public static IEnumerable<CertificateLocation> GetCertificateLocations()
        {
            var s = getNPKIDirectories();

            foreach (DirectoryInfo npkiDirectory in getNPKIDirectories().Select(i => new DirectoryInfo(i)))
            {
                foreach (var i in getCertDirectoriesFromDir(npkiDirectory))
                    yield return new CertificateLocation(Path.Combine(i, "signCert.der"), Path.Combine(i, "signPri.key"));
            }
        }
        private static IEnumerable<string> getCertDirectoriesFromDir(DirectoryInfo dir)
        {
            foreach (string i in from d in dir.GetDirectories() where Directory.Exists(Path.Combine(d.FullName, "USER")) select Path.Combine(d.FullName, "USER"))
                foreach (string j in from d in new DirectoryInfo(i).GetDirectories() select d.FullName)
                    yield return j;
        }
        private static IEnumerable<string> getNPKIDirectories()
        {
            return from i in getNPKIDirectoryCandidiates()
                   where Directory.Exists(i)
                   select i;
        }
        private static IEnumerable<string> getNPKIDirectoryCandidiates()
        {
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32S:
                case PlatformID.Win32Windows:
                case PlatformID.Win32NT:
                case PlatformID.WinCE:
                    yield return Environment.ExpandEnvironmentVariables(@"%UserProfile%\AppData\LocalLow\NPKI\");
                    yield return Environment.ExpandEnvironmentVariables(@"%ProgramFiles%\NPKI");
                    break;
                case PlatformID.Unix:
                    yield return Path.Combine(Environment.GetEnvironmentVariable("HOME"), "NPKI");
                    break;
                case PlatformID.MacOSX:
                    yield return Path.Combine(Environment.GetEnvironmentVariable("HOME"), "Library/Preferences/NPKI");
                    break;
                case PlatformID.Xbox: // ?
                    throw new PlatformNotSupportedException();
            }
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.DriveType == DriveType.Fixed || drive.DriveType == DriveType.Removable)
                {
                    yield return Path.Combine(drive.RootDirectory.FullName, "NPKI");
                }
            }
        }
    }
    public class CertificateLocation
    {
        internal CertificateLocation(string pubKeyPath, string priKeyPath)
        {
            PublicKeyCertificate = new X509Certificate2(pubKeyPath);
            EncryptedPrivateKeyInfo = new PKCS8.EncryptedPrivateKeyInfo(File.ReadAllBytes(priKeyPath));
            LocationDescription = Path.GetPathRoot(pubKeyPath);
        }
        public string LocationDescription { get; private set; }
        public X509Certificate2 PublicKeyCertificate { get; private set; }
        public PKCS8.EncryptedPrivateKeyInfo EncryptedPrivateKeyInfo { get; private set; }
        public PKCS8.PrivateKeyInfo PrivateKeyInfo { get; set; }
    }
}
