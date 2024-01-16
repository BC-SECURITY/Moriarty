using Moriarty.Msrc;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Linq;

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

            var vulnerabilities = new VulnerabilityCollection();
            ExecuteVulnerabilityChecks(vulnerabilities, buildNumber, installedKBs);
            vulnerabilities.ShowResults();
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

        private static void ExecuteVulnerabilityChecks(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            var typesWithCheckMethod = Assembly.GetExecutingAssembly()
                                               .GetTypes()
                                               .Where(t => t.Namespace == "Moriarty.Msrc"
                                                           && t.GetMethod("Check") != null);

            foreach (var type in typesWithCheckMethod)
            {
                MethodInfo checkMethod = type.GetMethod("Check", new Type[] { typeof(VulnerabilityCollection), typeof(int), typeof(List<int>) });
                if (checkMethod != null && checkMethod.IsStatic)
                {
                    checkMethod.Invoke(null, new object[] { vulnerabilities, buildNumber, installedKBs });
                }
            }
        }
    }
}