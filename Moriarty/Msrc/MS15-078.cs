using System;
using System.Diagnostics;
using System.IO;

namespace Moriarty.Msrc
{
    internal static class MS15_078
    {
        private const string Id = "MS15-078";
        private static readonly string[] Exploits = new[]
        {
            "https://www.exploit-db.com/exploits/38222/"
        };

        public static Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public static void Check(VulnerabilityCollection vulnerabilities)
        {
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string filePath = Path.Combine(systemRoot, "system32", "atmfd.dll");

            // Check if the file exists before accessing its version info
            if (File.Exists(filePath))
            {
                var versionInfo = FileVersionInfo.GetVersionInfo(filePath);
                int revision = versionInfo.FilePrivatePart;

                if (revision == 243)
                {
                    vulnerabilities.SetAsVulnerable(Id);
                }
            }
        }
    }
}
