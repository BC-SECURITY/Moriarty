using Moriarty.Msrc;
using System;
using System.Collections.Generic;

namespace Moriarty
{
    public interface IVulnerabilityCheck
    {
        void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs);
        Vulnerability GetVulnerability();
    }

    class Program
    {
        static List<IVulnerabilityCheck> localVulnerabilityChecks = new List<IVulnerabilityCheck>
        {
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
            new CVE_2017_7199(),
            new CVE_2020_0796(),
            new CVE_2021_1675(),
            new CVE_2021_44228(),
            new CVE_2022_40140(),
            new CVE_2022_22965(),
            new CVE_2021_26855(),
            new CVE_2021_36934(),
            new CVE_2021_26857(),
            new CVE_2021_27065(),
            new CVE_2021_26858(),
            new CVE_2022_34718(),
            new CVE_2023_36664(),
        };

        static List<IVulnerabilityCheck> remoteVulnerabilityChecks = new List<IVulnerabilityCheck>
        {
            new MS13_053(),
        };

        public static void Main(string[] args)
        {
            Info.PrintLogo();

            if (args.Length == 0)
            {
                Info.PrintHelp();
                return;
            }

            var targetMachines = new List<string>();
            bool runLocal = false;
            bool runRemote = false;

            foreach (var arg in args)
            {
                switch (arg.ToLower())
                {
                    case "--list-vulns":
                    case "-v":
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

                    case "--local":
                    case "-l":
                        runLocal = true;
                        break;

                    case "--remote":
                    case "-r":
                        runRemote = true;
                        var targetsIndex = Array.IndexOf(args, arg) + 1;
                        if (targetsIndex < args.Length)
                        {
                            targetMachines.AddRange(args[targetsIndex].Split(','));
                        }
                        break;
                }
            }

            // If debug mode is enabled
            DebugUtility.DebugPrint("Debug mode enabled.");

            if (runRemote)
            {
                foreach (var target in targetMachines)
                {
                    ScanRemoteMachine(target);
                }
            }

            if (runLocal)
            {
                ScanLocalMachine();
            }

            if (!runLocal && !runRemote)
            {
                Info.PrintHelp();
            }
        }

        private static void ScanLocalMachine()
        {
            var supportedVersions = new Dictionary<int, string>()
            {
                { 10240, "1507" }, { 10586, "1511" }, { 14393, "1607" }, { 15063, "1703" }, { 16299, "1709" },
                { 17134, "1803" }, { 17763, "1809" }, { 18362, "1903" }, { 18363, "1909" }, { 19041, "2004" },
                { 19042, "20H2" }, { 19043, "21H1" }, { 19044, "21H2" }, { 19045, "22H1" },
                { 22000, "21H2" }, { 22621, "22H2" }, { 22631, "23H2" },
            };

            var buildNumber = Wmi.GetBuildNumber();
            if (!supportedVersions.TryGetValue(buildNumber, out var version))
            {
                Console.Error.WriteLine(buildNumber != 0
                    ? $" [!] Warning: Windows version may not be supported. Build number: {buildNumber}. Proceeding with checks."
                    : " [!] Could not retrieve Windows Build Number. Proceeding with checks.");
            }

            Console.WriteLine($" [*] OS Version: {version} ({buildNumber})");

            Console.WriteLine(" [*] Enumerating installed KBs...");
            var installedKBs = Wmi.GetInstalledKBs();

            foreach (var kb in installedKBs)
            {
                DebugUtility.DebugPrint($"Installed KBs: {kb}");
            }

            Console.WriteLine(" [*] Evaluating potential CVEs...");
            var vulnerabilities = new VulnerabilityCollection(localVulnerabilityChecks);
            ExecuteLocalVulnerabilityChecks(vulnerabilities, buildNumber, installedKBs);
            vulnerabilities.ShowResults();
        }

        private static void ScanRemoteMachine(string target)
        {
            Console.WriteLine($" [*] Scanning remote machine: {target}");

            Console.WriteLine($" [*] Evaluating potential CVEs on {target}...");
            var vulnerabilities = new VulnerabilityCollection(remoteVulnerabilityChecks);
            ExecuteRemoteVulnerabilityChecks(vulnerabilities);
            vulnerabilities.ShowResults();
        }

        private static void ListVulnerabilities()
        {
            Console.WriteLine(" [*] Listing all vulnerabilities scanned by Moriarty:");
            Console.WriteLine(" [*] Local vulnerabilities:");
            var localVulnerabilities = new VulnerabilityCollection(localVulnerabilityChecks).GetAllVulnerabilities();
            foreach (var vulnerability in localVulnerabilities)
            {
                Console.WriteLine($"  - {vulnerability.Identification}");
            }
            Console.WriteLine();

            Console.WriteLine(" [*] Remote vulnerabilities:");
            var remoteVulnerabilities = new VulnerabilityCollection(remoteVulnerabilityChecks).GetAllVulnerabilities();
            foreach (var vulnerability in remoteVulnerabilities)
            {
                Console.WriteLine($"  - {vulnerability.Identification}");
            }
            Console.WriteLine();
        }

        private static void ExecuteLocalVulnerabilityChecks(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            foreach (var check in vulnerabilities.VulnerabilityChecks)
            {
                check.Check(vulnerabilities, buildNumber, installedKBs);
            }
        }

        private static void ExecuteRemoteVulnerabilityChecks(VulnerabilityCollection vulnerabilities)
        {
            foreach (var check in vulnerabilities.VulnerabilityChecks)
            {
                check.Check(vulnerabilities, 0, new List<int>()); // Assuming build number 0 and empty KB list for remote checks
            }
        }
    }
}
