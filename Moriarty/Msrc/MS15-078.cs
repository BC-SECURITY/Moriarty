using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;

namespace Moriarty.Msrc
{
    public class MS15_078 : IVulnerabilityCheck
    {
        private const string Id = "MS15-078";
        private static readonly string[] Exploits = new[]
        {
            "https://www.exploit-db.com/exploits/38222/"
        };

        public Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
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
