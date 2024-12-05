using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Agent
{
    class Program
    {
        private const string MachineID = "Win11-Virtual_Machine-- DEMO";
        private const string ApiUrl = "";
        private static readonly HttpClient HttpClient = new HttpClient();
        private static DateTime _lastSentTime;
        private static readonly HashSet<int> MonitoredEventIDs = new()
        {
            104, 106, 201, 740, 741, 1102, 1116, 1118, 1119, 1120, 4624, 4625,
            4634, 4647, 4648, 4656, 4672, 4697, 4698, 4699, 4700, 4701, 4702,
            4719, 4720, 4722, 4724, 4728, 4732, 4738, 4756, 4768, 4769, 4771,
            4776, 5001, 5140, 5142, 5145, 5157, 7034, 7036, 7040, 7045
        };

        private const int FailedLoginThreshold = 3;
        private static readonly TimeSpan MonitoringWindow = TimeSpan.FromMinutes(15);
        private static readonly Dictionary<string, int> FailedLoginAttempts = new();

        static async Task SendDataAsync(string jsonData)
        {
            try
            {
                var response = await HttpClient.PostAsync(ApiUrl, new StringContent(jsonData, Encoding.UTF8, "application/json"));
                if (!response.IsSuccessStatusCode)
                {
                    Console.WriteLine($"POST request failed: {response.StatusCode} - {await response.Content.ReadAsStringAsync()}");
                }
                else
                {
                    Console.WriteLine("POST request successful!");
                }
            }
            catch (HttpRequestException httpEx)
            {
                Console.WriteLine($"HTTP Request Exception: {httpEx.Message}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Exception occurred: {e.Message}\n{e.StackTrace}");
            }
        }

        static bool ShouldSendLog(EventLogEntry entry) => entry.TimeGenerated > _lastSentTime;

        static void ProcessEventLog(EventLogEntry entry)
        {
            if (!MonitoredEventIDs.Contains(entry.EventID) || !ShouldSendLog(entry)) return;

            var logData = FormatLogData(entry); // Get the plain string (comma-separated values)
            _ = SendDataAsync(logData);

            if (entry.EventID == 4625) HandleFailedLogin(entry);
        }

        static string FormatLogData(EventLogEntry entry)
        {
            // Format the log data as a comma-separated string
            var logData = $"{entry.EventID},{MachineID},{entry.CategoryNumber},{entry.Index},{entry.TimeGenerated:yyyy-MM-ddTHH:mm:ss.fffzzz}";
            return logData;
        }

        static void HandleFailedLogin(EventLogEntry entry)
{
    var ipAddress = ExtractIPAddress(entry.Message);
    if (string.IsNullOrEmpty(ipAddress)) return;

    UpdateFailedLoginAttempts(ipAddress);

    if (FailedLoginAttempts[ipAddress] >= FailedLoginThreshold && !IsLocalhost(ipAddress))
    {
        BlockIp(ipAddress);

        // Create JSON object for brute force tracking
        var blockData = new
        {
            event_id = 4625,
            machine_id = MachineID,
            timestamp = entry.TimeGenerated.ToString("o"), // ISO 8601 format
            ip = ipAddress,
            blocked_ip = ipAddress,
            attempts = FailedLoginAttempts[ipAddress]
        };

        // Serialize the JSON object and send it
        var jsonData = JsonConvert.SerializeObject(blockData);
        _ = SendDataAsync(jsonData);

        FailedLoginAttempts[ipAddress] = 0; // Reset count after blocking
    }
    else
    {
        // Send an update event without blocking
        var updateData = new
        {
            event_id = 4625,
            machine_id = MachineID,
            timestamp = entry.TimeGenerated.ToString("o"),
            ip = ipAddress,
            attempts = FailedLoginAttempts[ipAddress]
        };

        var jsonData = JsonConvert.SerializeObject(updateData);
        _ = SendDataAsync(jsonData);
    }
}


        static void UpdateFailedLoginAttempts(string ipAddress)
        {
            lock (FailedLoginAttempts)
            {
                FailedLoginAttempts[ipAddress] = FailedLoginAttempts.GetValueOrDefault(ipAddress) + 1;
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

        static void EventParser()
        {
            using var eventLog = new EventLog("Security") { EnableRaisingEvents = true };
            eventLog.EntryWritten += (sender, e) => ProcessEventLog(e.Entry);

            Console.WriteLine("Press any key to exit....");
            Console.Read();
        }

        static void Main()
        {
            _lastSentTime = DateTime.Now;
            EventParser();
        }
    }
}
