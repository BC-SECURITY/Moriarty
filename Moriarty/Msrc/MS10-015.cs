using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;

namespace Moriarty.Msrc
{
    internal static class MS10_015
    {
        private const string Id = "MS10-015";
        private static readonly string[] Exploits = new[]
        {
            "https://www.exploit-db.com/exploits/11199/"
        };

        public static Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public static void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            if (Environment.Is64BitOperatingSystem)
            {
                // 64-bit systems are not vulnerable
                return;
            }

            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string filePath = Path.Combine(systemRoot, "system32", "ntoskrnl.exe");
            var versionInfo = FileVersionInfo.GetVersionInfo(filePath);

            int build = versionInfo.FileBuildPart;
            int revision = versionInfo.FilePrivatePart;

            if (build == 7600 && revision <= 20591)
            {
                vulnerabilities.SetAsVulnerable(Id);
            }
        }
    }
}
