using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Moriarty.Msrc
{
    public class CVE_2021_26855 : IVulnerabilityCheck
    {
        private const string Id = "CVE-2021-26855 (ProxyLogon)";
        private static readonly string[] Exploits = new[]
        {
            "https://github.com/cert-lv/exchange_webshell_detection"
        };

        private readonly string[] _keywords = new[]
        {
            "wscript", "vbscript", "visualbasic", "jscript", "eval\\s?\\(", "process\\s?\\(", "eval_r", "executestatement",
            "processstartinfo", "os.run", "oscript.run", "oshell.run", "convert.frombase64string", "request.headers",
            "createobject", "filesystemobject", "httppostedfile", "system.io.file", "writealltext", "cmd.exe",
            "cmd /c", "powershell.exe", "net user", "net group", "lsass.exe", "procdump", "whoami", "ping.exe",
            "new socket", "binarywrite", "assembly.load", "compileassemblyfromsource", "aesenc", "webshell"
        };

        public Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            DebugUtility.DebugPrint("Running CVE-2021-26855 (ProxyLogon) checks...");
            CheckAsync(vulnerabilities, buildNumber, installedKBs).GetAwaiter().GetResult();
        }

        private async Task CheckAsync(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            var exchangeInstallPath = Environment.GetEnvironmentVariable("exchangeinstallpath");
            if (string.IsNullOrWhiteSpace(exchangeInstallPath))
            {
                DebugUtility.DebugPrint("Could not detect Exchange installation directory");
                return;
            }

            var frontendPath = Path.Combine(exchangeInstallPath, "Frontend");
            if (!Directory.Exists(frontendPath))
            {
                DebugUtility.DebugPrint("Frontend directory not found in Exchange installation path.");
                return;
            }

            var affected = false;

            var files = Directory.GetFiles(frontendPath, "*", SearchOption.AllDirectories);
            foreach (var file in files)
            {
                var content = await ReadFileContentAsync(file);
                if (_keywords.Any(keyword => Regex.IsMatch(content, keyword, RegexOptions.IgnoreCase)))
                {
                    DebugUtility.DebugPrint($"Found suspicious file: {file}");
                    affected = true;
                }
            }

            if (affected)
            {
                DebugUtility.DebugPrint("Server requires further examination.");
                vulnerabilities.SetAsVulnerable(Id);
            }
            else
            {
                DebugUtility.DebugPrint("No webshells found, but further examination is recommended.");
            }
        }
        private static async Task<string> ReadFileContentAsync(string filePath)
        {
            using (var reader = new StreamReader(filePath))
            {
                return await reader.ReadToEndAsync();
            }
        }
    }
}