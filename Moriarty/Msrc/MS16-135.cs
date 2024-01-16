using System;
using System.Diagnostics;
using System.IO;
using System.Collections.Generic;

namespace Moriarty.Msrc
{
    internal static class MS16_135
    {
        private const string Id = "MS16-135";
        private static readonly string[] Exploits = new[]
        {
            "https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135"
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
            if ((build == 7601 && revision < 23584) ||
                (build == 9600 && revision <= 18524) ||
                (build == 10240 && revision <= 16384) ||
                (build == 10586 && revision <= 19) ||
                (build == 14393 && revision <= 446))
            {
                vulnerabilities.SetAsVulnerable(Id);
            }
        }
    }
}
