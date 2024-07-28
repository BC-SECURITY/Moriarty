using System;

namespace Moriarty
{
    public class Info
    {
        public static void PrintLogo()
        {
            Console.WriteLine();
            Console.WriteLine("███    ███  ██████  ██████  ██  █████  ██████  ████████ ██    ██ ");
            Console.WriteLine("████  ████ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██     ██  ██  ");
            Console.WriteLine("██ ████ ██ ██    ██ ██████  ██ ███████ ██████     ██      ████   ");
            Console.WriteLine("██  ██  ██ ██    ██ ██   ██ ██ ██   ██ ██   ██    ██       ██    ");
            Console.WriteLine("██      ██  ██████  ██   ██ ██ ██   ██ ██   ██    ██       ██    ");
            Console.WriteLine("                                                 v1.2");
            Console.WriteLine("                                                 BC Security\r\n");
        }
        public static void PrintHelp()
        {
            Console.WriteLine("Usage: Moriarty.exe [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  -h, --help       Display this help message.");
            Console.WriteLine("  -d, --debug      Run in debug mode for additional output.");
            Console.WriteLine("  --local, -l      Scan the local machine for vulnerabilities.");
            Console.WriteLine("  --remote, -r     Scan remote machines for vulnerabilities. Specify targets as comma-separated list.");
            Console.WriteLine("  -v, --list-vulns List all vulnerabilities that are scanned for.");
            Console.WriteLine("\nExamples:");
            Console.WriteLine("  Moriarty.exe --list-vulns");
            Console.WriteLine("  Moriarty.exe --local");
            Console.WriteLine("  Moriarty.exe --remote 192.168.1.100,192.168.1.101");
            Console.WriteLine();
        }
    }
}
