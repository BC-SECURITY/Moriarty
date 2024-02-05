using Moriarty.Msrc;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace Moriarty
{
    class Program
    {
        static void Main(string[] args)
        {
            Info.PrintLogo();
            foreach (var arg in args)
            {
                switch (arg.ToLower())
                {
                    case "--list-vulns":
                    case "-l":
                        ListVulnerabilities();
                        return;

                    case "--debug":
                    case "-d":
                        DebugUtility.IsDebugEnabled = true;
                        break;

                    case "--help":
                    case "-h":
                        Info.PrintHelp();
                        return;
                }
            }

            // If debug mode is enabled
            DebugUtility.DebugPrint("Debug mode enabled.");

            var supportedVersions = new Dictionary<int, string>()
            {
                { 10240, "1507" }, { 10586, "1511" }, { 14393, "1607" }, { 15063, "1703" }, { 16299, "1709" },
                { 17134, "1803" }, { 17763, "1809" }, { 18362, "1903" }, { 18363, "1909" }, { 19041, "2004" },
                { 19042, "20H2" }, { 19043, "21H1" }, { 19044, "21H2" },
                { 22000, "21H2" }, { 22621, "22H2" }
            };

            var buildNumber = Wmi.GetBuildNumber();

            if (!supportedVersions.TryGetValue(buildNumber, out var version))
            {
                Console.Error.WriteLine(buildNumber != 0
                    ? " [!] Windows version not supported"
                    : " [!] Could not retrieve Windows BuildNumber");
                return;
            }

            Console.WriteLine($" [*] OS Version: {version} ({buildNumber})");

            Console.WriteLine(" [*] Enumerating installed KBs...");
            var installedKBs = Wmi.GetInstalledKBs();

            foreach (var kb in installedKBs)
            {
                DebugUtility.DebugPrint($"Installed KBs: {kb}");
            }

            // List of Vulnerabilities
            var vulnerabiltiies = new VulnerabilityCollection();

            // Check each one
            MS10_015.Check(vulnerabiltiies);
            MS10_092.Check(vulnerabiltiies);
            MS13_053.Check(vulnerabiltiies);
            MS13_081.Check(vulnerabiltiies);
            MS14_058.Check(vulnerabiltiies);
            MS15_051.Check(vulnerabiltiies);
            MS15_078.Check(vulnerabiltiies);
            MS16_016.Check(vulnerabiltiies);
            MS16_032.Check(vulnerabiltiies);
            MS16_034.Check(vulnerabiltiies);
            MS16_135.Check(vulnerabiltiies);
            CVE_2017_7199.Check(vulnerabiltiies);
            CVE_2019_0836.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_0841.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_1064.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_1130.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_1253.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_1315.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_1385.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_1388.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2019_1405.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2020_0668.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2020_0683.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2020_0796.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2020_1013.Check(vulnerabiltiies, buildNumber, installedKBs);
            CVE_2023_36664.Check(vulnerabiltiies);
            CVE_2021_1675.Check(vulnerabiltiies);
            CVE_2021_44228.Check(vulnerabiltiies);
            CVE_2022_40140.Check(vulnerabiltiies);
            CVE_2022_22965.Check(vulnerabiltiies);

            // Print the results
            vulnerabiltiies.ShowResults();
        }
        private static void ListVulnerabilities()
        {
            Console.WriteLine(" [*] Listing all vulnerabilities scanned by Moriarty:");
            var vulnerabilities = new VulnerabilityCollection().GetAllVulnerabilities();
            foreach (var vulnerability in vulnerabilities)
            {
                Console.WriteLine($"  - {vulnerability.Identification}");
            }
            Console.WriteLine();
        }
    }
}
