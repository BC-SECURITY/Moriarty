using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Sockets;

namespace Moriarty.Msrc
{
    public class MS17_010 : IVulnerabilityCheck
    {
        private const string Id = "MS17-010";
        private static readonly string[] Exploits = new[]
        {
            "https://github.com/worawit/MS17-010"
        };
        private string _targetIp;

        public MS17_010(string targetIp)
        {
            _targetIp = targetIp;
        }

        public Vulnerability GetVulnerability()
        {
            return new Vulnerability(Id, Exploits);
        }

        public void Check(VulnerabilityCollection vulnerabilities, int buildNumber, List<int> installedKBs)
        {
            int port = 445;

            try
            {
                using (var client = new TcpClient(_targetIp, port))
                {
                    using (var stream = client.GetStream())
                    {
                        if (CheckMS17010(stream))
                        {
                            Console.WriteLine("[!] The target is not patched.");
                            vulnerabilities.SetAsVulnerable(Id);
                        }
                        else
                        {
                            Console.WriteLine("[-] The target is patched.");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] Error: " + ex.Message);
            }
        }

        private bool CheckMS17010(NetworkStream stream)
        {
            byte[] payload = new byte[]
            {
                0x00, 0x00, 0x00, 0x90, 0xff, 0x53, 0x4d, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
                0x17, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xFE, 0xDA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02, 0x50, 0x43,
                0x20, 0x4E, 0x45, 0x54, 0x57, 0x4F, 0x52, 0x4B, 0x20, 0x50, 0x52, 0x4F, 0x47, 0x52, 0x41, 0x4D,
                0x20, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00,
                0x02, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x77, 0x73, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x57, 0x6F, 0x72,
                0x6B, 0x67, 0x72, 0x6F, 0x75, 0x70, 0x73, 0x20, 0x33, 0x2E, 0x31, 0x61, 0x00, 0x02, 0x4C, 0x4D,
                0x31, 0x2E, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x32,
                0x2E, 0x31, 0x00, 0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00
            };

            try
            {
                stream.Write(payload, 0, payload.Length);
                byte[] buffer = new byte[1024];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);

                if (bytesRead > 0 && buffer[9] == 0x72)
                {
                    uint status = BitConverter.ToUInt32(buffer, 5);
                    if (status == 0xC0000205) // STATUS_INSUFF_SERVER_RESOURCES
                    {
                        return true;
                    }
                }
            }
            catch (IOException ex)
            {
                Console.WriteLine("[-] Network error: " + ex.Message);
            }

            return false;
        }
    }
}
