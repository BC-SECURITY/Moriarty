using System;
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

            // Check if the ExchangeInstallPath environment variable is not set or empty
            if (string.IsNullOrWhiteSpace(exchangeInstallPath))
            {
                DebugUtility.DebugPrint("ExchangeInstallPath environment variable is not set or is empty. Cannot proceed with checks.");
                return; // Exit the method as we can't proceed without the installation path
            }

            string[] logPaths = {
        Path.Combine(exchangeInstallPath, @"V15\Logging\OABGeneratorLog\*.log"),
        Path.Combine(exchangeInstallPath, @"Logging\OABGeneratorLog\*.log")
    };

            string outputPath = Path.Combine(Environment.GetEnvironmentVariable("SystemRoot"), "temp", Environment.MachineName + "-exch", "OABGeneratorLog.txt");
            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)); // Ensure the output directory exists

            bool foundSuspiciousData = false;

            foreach (var logPath in logPaths)
            {
                if (Directory.Exists(Path.GetDirectoryName(logPath)))
                {
                    var logFiles = Directory.GetFiles(Path.GetDirectoryName(logPath), "*.log");
                    foreach (var logFile in logFiles)
                    {
                        var lines = File.ReadAllLines(logFile);
                        var suspiciousLines = lines.Where(line => line.Contains("Download failed and temporary file"));
                        if (suspiciousLines.Any())
                        {
                            File.AppendAllLines(outputPath, suspiciousLines);
                            foundSuspiciousData = true;
                        }
                    }
                }
            }

            if (foundSuspiciousData)
            {
                DebugUtility.DebugPrint($"Suspicious data in OAB Logs. See {outputPath} for details.");
                vulnerabilities.SetAsVulnerable(Id);
            }
            else
            {
                File.WriteAllText(outputPath, "Nothing Suspicious in OAB Logs");
                DebugUtility.DebugPrint("Nothing Suspicious in OAB Logs");
            }
        }
    }
}
