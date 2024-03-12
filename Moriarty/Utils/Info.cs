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
            Console.WriteLine("                                                 v1.1");
            Console.WriteLine("                                                 BC Security\r\n");
        }
        public static void PrintHelp()
        {
            Console.WriteLine("Usage: Moriarty.exe [options]");
            Console.WriteLine("Options:");
            Console.WriteLine("  -h, --help       Display this help message.");
            Console.WriteLine("  -d, --debug      Run in debug mode for additional output.");
            Console.WriteLine("  -l, --list-vulns List all vulnerabilities that are scanned for.");
            Console.WriteLine("\nExamples:");
            Console.WriteLine("  Moriarty.exe -d");
            Console.WriteLine("  Moriarty.exe --list-vulns");
            Console.WriteLine();
        }
    }
}
