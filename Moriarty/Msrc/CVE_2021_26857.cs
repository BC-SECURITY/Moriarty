﻿using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Moriarty.Msrc
{
    public class CVE_2021_26857 : IVulnerabilityCheck
    {
        private const string Id = "CVE-2021-26857";
        private static readonly string[] Exploits = new[]
        {
            "https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2021-26857"
        };

        public Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            DebugUtility.DebugPrint("Running CVE-2021-26857 checks...");

            string exchangeInstallPath = Environment.GetEnvironmentVariable("ExchangeInstallPath");
            if (string.IsNullOrEmpty(exchangeInstallPath))
            {
                DebugUtility.DebugPrint("ExchangeInstallPath environment variable is not set or empty. Cannot proceed with CVE-2021-26857 checks.");
                return;
            }

            string logPath = Path.Combine(exchangeInstallPath, @"V15\Logging\OABGeneratorLog\");
            if (Directory.Exists(logPath) && Directory.GetFiles(logPath, "*.log").Any())
            {
                DebugUtility.DebugPrint("Potential CVE-2021-26857 exploitability detected due to the presence of OABGenerator logs.");
                vulnerabilities.SetAsVulnerable(Id);
            }
            else
            {
                DebugUtility.DebugPrint("No OABGenerator logs found. System likely not exploitable for CVE-2021-26857.");
            }
        }
    }
}
