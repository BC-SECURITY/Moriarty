using Moriarty.Msrc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Linq;

namespace Moriarty
{
    public interface IVulnerabilityCheck
    {
        void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs);
        Vulnerability GetVulnerability();
    }

    class Program
    {
        static List<IVulnerabilityCheck> vulnerabilityChecks = new List<IVulnerabilityCheck>
        {
            new CVE_2019_0836(),
            new CVE_2019_0841(),
            new CVE_2019_1064(),
            new CVE_2019_1130(),
            new CVE_2019_1253(),
            new CVE_2019_1315(),
            new CVE_2019_1385(),
            new CVE_2019_1388(),
            new CVE_2019_1405(),
            new CVE_2020_0668(),
            new CVE_2020_0683(),
            new CVE_2020_1013(),
            new MS10_015(),
            new MS10_092(),
            new MS13_053(),
            new MS13_081(),
            new MS14_058(),
            new MS15_051(),
            new MS15_078(),
            new MS16_016(),
            new MS16_032(),
            new MS16_034(),
            new MS16_135(),
            new CVE_2017_7199(),
            new CVE_2020_0796(),
            new CVE_2023_36664(),
            new CVE_2021_1675(),
            new CVE_2021_44228(),
            new CVE_2022_40140(),
            new CVE_2022_22965(),
            new CVE_2021_26855(),
            new CVE_2021_36934(),
        };

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
                { 22000, "21H2" }, { 22621, "22H2" }, { 22631, "23H2" },
            };

            var buildNumber = Wmi.GetBuildNumber();

            if (!supportedVersions.TryGetValue(buildNumber, out var version))
            {
                Console.Error.WriteLine(buildNumber != 0
                    ? $" [!] Windows version not supported. Build number: {buildNumber}"
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

            var vulnerabilities = new VulnerabilityCollection(vulnerabilityChecks);
            ExecuteVulnerabilityChecks(vulnerabilities, buildNumber, installedKBs);
            vulnerabilities.ShowResults();
        }

        private static void ListVulnerabilities()
        {
            Console.WriteLine(" [*] Listing all vulnerabilities scanned by Moriarty:");
            var vulnerabilities = new VulnerabilityCollection(vulnerabilityChecks).GetAllVulnerabilities();
            foreach (var vulnerability in vulnerabilities)
            {
                Console.WriteLine($"  - {vulnerability.Identification}");
            }
            Console.WriteLine();
        }

        private static void ExecuteVulnerabilityChecks(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            foreach (var check in vulnerabilityChecks)
            {
                check.Check(vulnerabilities, buildNumber, installedKBs);
            }
        }
    }
}