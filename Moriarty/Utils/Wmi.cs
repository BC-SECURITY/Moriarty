using System;
using System.Collections.Generic;
using System.Management;

namespace Moriarty
{
    public class Wmi
    {
        public static List<int> GetInstalledKBs()
        {
            var kbList = new List<int>();

            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\cimv2", "SELECT HotFixID FROM Win32_QuickFixEngineering"))
                {
                    foreach (ManagementObject hotFix in searcher.Get())
                    {
                        string hotFixID = hotFix["HotFixID"]?.ToString();
                        if (hotFixID != null && hotFixID.StartsWith("KB") && int.TryParse(hotFixID.Substring(2), out int kb))
                        {
                            kbList.Add(kb);
                        }
                    }
                }
            }
            catch (ManagementException e)
            {
                Console.Error.WriteLine($" [!] Error retrieving KBs: {e.Message}");
            }

            return kbList;
        }

        public static int GetBuildNumber()
        {
            try
            {
                using (var searcher = new ManagementObjectSearcher(@"root\cimv2", "SELECT BuildNumber FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject obj in searcher.Get())
                    {
                        if (int.TryParse(obj["BuildNumber"]?.ToString(), out int buildNumber))
                        {
                            return buildNumber;
                        }
                    }
                }
            }
            catch (ManagementException e)
            {
                Console.Error.WriteLine($" [!] Error retrieving Build Number: {e.Message}");
            }

            return 0;
        }
        public static int GetRemoteBuildNumber(string target)
        {
            var options = new ConnectionOptions();
            var scope = new ManagementScope($"\\\\{target}\\root\\cimv2", options);

            try
            {
                scope.Connect();
                using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT BuildNumber FROM Win32_OperatingSystem")))
                {
                    foreach (var queryObj in searcher.Get())
                    {
                        if (int.TryParse(queryObj["BuildNumber"].ToString(), out int buildNumber))
                        {
                            return buildNumber;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($" [!] Error connecting to {target}: {ex.Message}");
            }

            return 0;
        }

        public static List<int> GetRemoteInstalledKBs(string target)
        {
            var installedKBs = new List<int>();
            var options = new ConnectionOptions();
            var scope = new ManagementScope($"\\\\{target}\\root\\cimv2", options);

            try
            {
                scope.Connect();
                using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT HotFixID FROM Win32_QuickFixEngineering")))
                {
                    foreach (var queryObj in searcher.Get())
                    {
                        if (queryObj["HotFixID"] != null && int.TryParse(queryObj["HotFixID"].ToString().Replace("KB", ""), out int kbNumber))
                        {
                            installedKBs.Add(kbNumber);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($" [!] Error connecting to {target}: {ex.Message}");
            }

            return installedKBs;
        }
    }
}
