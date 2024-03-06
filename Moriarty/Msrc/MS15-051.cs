using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;

namespace Moriarty.Msrc
{
    public class MS15_051 : IVulnerabilityCheck
    {
        private const string Id = "MS15-051";
        private static readonly string[] Exploits = new[]
        {
            "https://www.exploit-db.com/exploits/37367/"
        };

        public Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string filePath;

            // If the process is 64-bit, or if the operating system is 32-bit, use 'system32'
            if (Environment.Is64BitProcess || !Environment.Is64BitOperatingSystem)
            {
                filePath = Path.Combine(systemRoot, "system32", "win32k.sys");
            }
            else // If the process is 32-bit and the operating system is 64-bit, use 'sysnative'
            {
                filePath = Path.Combine(systemRoot, "sysnative", "win32k.sys");
            }

            var versionInfo = FileVersionInfo.GetVersionInfo(filePath);

            int build = versionInfo.FileBuildPart;
            int revision = versionInfo.FilePrivatePart;

            // Implementing the vulnerability check logic
            if ((build == 7600 && revision <= 18000) ||
                (build == 7601 && revision <= 22823) ||
                (build == 9200 && revision <= 21247) ||
                (build == 9600 && revision <= 17353))
            {
                vulnerabilities.SetAsVulnerable(Id);
            }
        }
    }
}
