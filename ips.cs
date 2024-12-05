using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Agent
{
    class Program
    {
        private const int FailedLoginThreshold = 3;
        private static readonly Dictionary<string, int> FailedLoginAttempts = new();

        static void Main()
        {
            EventParser();
        }

        static void EventParser()
        {
            using var eventLog = new EventLog("Security") { EnableRaisingEvents = true };
            eventLog.EntryWritten += (sender, e) => HandleFailedLogin(e.Entry);

            Console.WriteLine("Monitoring for brute force attacks. Press any key to exit...");
            Console.ReadKey();
        }

        static void HandleFailedLogin(EventLogEntry entry)
        {
            if (entry.EventID != 4625) return;

            var ipAddress = ExtractIPAddress(entry.Message);
            if (string.IsNullOrEmpty(ipAddress)) return;

            UpdateFailedLoginAttempts(ipAddress);

            if (FailedLoginAttempts[ipAddress] >= FailedLoginThreshold && !IsLocalhost(ipAddress))
            {
                BlockIp(ipAddress);
                FailedLoginAttempts[ipAddress] = 0; // Reset count after blocking
                Console.WriteLine($"Blocked IP {ipAddress} after {FailedLoginThreshold} failed attempts.");
            }
            else
            {
                Console.WriteLine($"Failed login attempt from IP {ipAddress}. Attempt #{FailedLoginAttempts[ipAddress]}.");
            }
        }

        static void UpdateFailedLoginAttempts(string ipAddress)
        {
            lock (FailedLoginAttempts)
            {
                if (FailedLoginAttempts.ContainsKey(ipAddress))
                    FailedLoginAttempts[ipAddress]++;
                else
                    FailedLoginAttempts[ipAddress] = 1;
            }
        }

        static bool IsLocalhost(string ipAddress) => ipAddress == "127.0.0.1" || ipAddress == "::1";

        static string ExtractIPAddress(string message)
        {
            const string ipPattern = @"(?<=Source Network Address:\s)([^\s]+)";
            var match = Regex.Match(message, ipPattern);
#pragma warning disable CS8603 // Possible null reference return.
            return match.Success ? match.Value : null;
#pragma warning restore CS8603 // Possible null reference return.
        }

        static void BlockIp(string ipAddress)
        {
            if (IsIpBlocked(ipAddress))
            {
                Console.WriteLine($"IP {ipAddress} is already blocked. Skipping rule creation.");
                return;
            }

            var command = $"netsh advfirewall firewall add rule name=\"Block {ipAddress}\" dir=in action=block remoteip={ipAddress}";
            ExecuteCommand(command);
        }

        static bool IsIpBlocked(string ipAddress)
        {
            var checkCommand = $"netsh advfirewall firewall show rule name=all | findstr \"{ipAddress}\"";
            var output = ExecuteCommandWithOutput(checkCommand);
            return !string.IsNullOrEmpty(output);
        }

        static void ExecuteCommand(string command)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    FileName = "cmd.exe",
                    Arguments = "/C " + command,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();
        }

        static string ExecuteCommandWithOutput(string command)
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    WindowStyle = ProcessWindowStyle.Hidden,
                    FileName = "cmd.exe",
                    Arguments = "/C " + command,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            return output;
        }
    }
}
