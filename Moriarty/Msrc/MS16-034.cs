using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;

namespace Moriarty.Msrc
{
    internal static class MS16_034
    {
        private const string Id = "MS16-034";
        private static readonly string[] Exploits = new[]
        {
            "https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034"
        };

        public static Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public static void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
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

            // Implementing the vulnerability check logic based on build and revision
            if ((build == 6002 && revision < 19597) ||
                (build == 7601 && revision < 19145) ||
                (build == 9200 && revision < 17647) ||
                (build == 9600 && revision < 18228))
            {
                vulnerabilities.SetAsVulnerable(Id);
            }
        }
    }
}
