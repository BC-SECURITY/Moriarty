using System;
using System.Diagnostics;
using System.IO;

namespace Moriarty.Msrc
{
    internal static class MS10_092
    {
        private const string Id = "MS10-092";
        private static readonly string[] Exploits = new[]
        {
            "https://www.exploit-db.com/exploits/19930/"
        };

        public static Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public static void Check(VulnerabilityCollection vulnerabilities)
        {
            string systemRoot = Environment.GetEnvironmentVariable("SystemRoot");
            string filePath;

            // If the process is 64-bit, or if the operating system is 32-bit, use 'system32'
            if (Environment.Is64BitProcess || !Environment.Is64BitOperatingSystem)
            {
                filePath = Path.Combine(systemRoot, "system32", "schedsvc.dll");
            }
            else // If the process is 32-bit and the operating system is 64-bit, use 'sysnative'
            {
                filePath = Path.Combine(systemRoot, "sysnative", "schedsvc.dll");
            }

            var versionInfo = FileVersionInfo.GetVersionInfo(filePath);

            int build = versionInfo.FileBuildPart;
            int revision = versionInfo.FilePrivatePart;

            if (build == 7600 && revision <= 20830)
            {
                vulnerabilities.SetAsVulnerable(Id);
            }
        }
    }
}
