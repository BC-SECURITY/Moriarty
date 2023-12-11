using System;
using System.Diagnostics;
using System.IO;

namespace Moriarty.Msrc
{
    internal static class MS16_016
    {
        private const string Id = "MS16-016";
        private static readonly string[] Exploits = new[]
        {
            "https://www.exploit-db.com/exploits/40085/"
        };

        public static Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public static void Check(VulnerabilityCollection vulnerabilities)
        {
            if (Environment.Is64BitOperatingSystem)
            {
                // 64-bit systems are not vulnerable
                return;
            }

            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string filePath = Path.Combine(systemRoot, "system32", "drivers", "mrxdav.sys");
            var versionInfo = FileVersionInfo.GetVersionInfo(filePath);

            int build = versionInfo.FileBuildPart;
            int revision = versionInfo.FilePrivatePart;

            // Implementing the vulnerability check logic
            if ((build == 7600 && revision <= 16000) ||
                (build == 7601 && revision <= 23317) ||
                (build == 9200 && revision <= 21738) ||
                (build == 9600 && revision <= 18189) ||
                (build == 10240 && revision <= 16683) ||
                (build == 10586 && revision <= 103))
            {
                vulnerabilities.SetAsVulnerable(Id);
            }
        }
    }
}
