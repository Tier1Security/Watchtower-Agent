using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Agent
{
    // Define the EventPayload class
    public class EventPayload
    {
        [JsonProperty("event_id")]
        public int EventId { get; set; }

        [JsonProperty("license")]
        public string License { get; set; }

        [JsonProperty("category_number")]
        public int CategoryNumber { get; set; }

        [JsonProperty("log_index")]
        public int LogIndex { get; set; }

        [JsonProperty("timestamp")]
        public string Timestamp { get; set; }

        [JsonProperty("ip")]
        public string Ip { get; set; }

        [JsonProperty("attempts")]
        public int Attempts { get; set; }

        [JsonProperty("blocked_ip")]
        public string? BlockedIp { get; set; }
    }

    class Program
    {
        private const string license = "<LICENSE_KEY>";
        private const string ApiUrl = "https://www.tier1security.org/api";

        // Threshold for failed login attempts
        private const int FailedLoginThreshold = 5;

        private static readonly HttpClient HttpClient = new HttpClient();
        private static readonly HashSet<int> MonitoredEventIDs = new()
        {
            104, 106, 201, 740, 741, 1102, 1116, 1118, 1119, 1120,
            4624, 4625, 4634, 4647, 4648, 4656, 4672, 4697, 4698,
            4699, 4700, 4701, 4702, 4719, 4720, 4722, 4724, 4728,
            4732, 4738, 4756, 4768, 4769, 4771, 4776, 5001, 5140,
            5142, 5145, 5157, 7034, 7036, 7040, 7045,
        };

        private static readonly ConcurrentDictionary<string, int> FailedLoginAttempts = new();
        private static readonly HashSet<string> SentLogHashes = new();
        private static readonly object LogHashLock = new();
        private static DateTime ProgramStartTime;

        static async Task Main()
        {
            ProgramStartTime = DateTime.Now; // Record the program's start time

            if (!IsApiUrlValid(ApiUrl))
            {
                Console.WriteLine("API URL is not properly set. Exiting...");
                return;
            }

            await StartEventParsingAsync();
        }

        private static async Task StartEventParsingAsync()
        {
            using var eventLog = new EventLog("Security") { EnableRaisingEvents = true };

            eventLog.EntryWritten += async (sender, e) => await ProcessEventLogAsync(e.Entry);

            Console.WriteLine("Monitoring Security event logs. Press any key to exit...");
            await Task.Run(() => Console.ReadKey());
        }

        private static async Task ProcessEventLogAsync(EventLogEntry entry)
        {
            // Ignore events that occurred before the program started
            if (entry.TimeGenerated < ProgramStartTime)
            {
                Console.WriteLine($"Skipping old EventID: {entry.EventID}, Time: {entry.TimeGenerated}");
                return;
            }

            if (!MonitoredEventIDs.Contains(entry.EventID))
                return;

            if (IsDuplicateLog(entry))
            {
                Console.WriteLine($"Duplicate log detected. Skipping EventID: {entry.EventID}, Index: {entry.Index}");
                return;
            }

            if (entry.EventID != 4625)
            {
                var generalPayload = new EventPayload
                {
                    EventId = entry.EventID,
                    License = license,
                    CategoryNumber = entry.CategoryNumber,
                    LogIndex = entry.Index,
                    Timestamp = entry.TimeGenerated.ToString("o"),
                    Ip = string.Empty,
                    Attempts = 0,
                    BlockedIp = null,
                };

                await SendDataAsync(generalPayload);
            }

            if (entry.EventID == 4625)
            {
                await HandleFailedLoginAsync(entry);
            }
        }

        private static bool IsDuplicateLog(EventLogEntry entry)
        {
            // Compute a hash for the event
            string logHash = ComputeLogHash(entry);

            lock (LogHashLock)
            {
                if (SentLogHashes.Contains(logHash))
                {
                    return true;
                }

                SentLogHashes.Add(logHash);

                // Prevent memory bloat by limiting the size of the hash set
                if (SentLogHashes.Count > 5000)
                {
                    SentLogHashes.Clear();
                }

                return false;
            }
        }

        private static string ComputeLogHash(EventLogEntry entry)
        {
            using var sha256 = SHA256.Create();
            string logData = $"{entry.Index}-{entry.TimeGenerated}-{entry.EventID}-{entry.Message}";
            byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(logData));
            return Convert.ToBase64String(hashBytes);
        }

        private static async Task HandleFailedLoginAsync(EventLogEntry entry)
        {
            string ipAddress = ExtractIPAddress(entry.Message);

            if (string.IsNullOrEmpty(ipAddress) || !IPAddress.TryParse(ipAddress, out _))
            {
                Console.WriteLine($"Invalid or missing IP address in event {entry.Index}.");
                return;
            }

            lock (FailedLoginAttempts)
            {
                IncrementFailedLoginAttempt(ipAddress);
            }

            int attempts = FailedLoginAttempts[ipAddress];
            bool shouldBlock = attempts >= FailedLoginThreshold && !IsLocalhost(ipAddress);

            if (shouldBlock && BlockIp(ipAddress))
            {
                lock (FailedLoginAttempts)
                {
                    FailedLoginAttempts[ipAddress] = 0;
                }

                var eventPayload = new EventPayload
                {
                    EventId = 4625,
                    License = license,
                    CategoryNumber = entry.CategoryNumber,
                    LogIndex = entry.Index,
                    Timestamp = entry.TimeGenerated.ToString("o"),
                    Ip = ipAddress,
                    Attempts = attempts,
                    BlockedIp = ipAddress,
                };

                Console.WriteLine($"IP {ipAddress} has been blocked after {attempts} failed attempts.");
                await SendDataAsync(eventPayload);
            }
            else
            {
                var eventPayload = new EventPayload
                {
                    EventId = 4625,
                    License = license,
                    CategoryNumber = entry.CategoryNumber,
                    LogIndex = entry.Index,
                    Timestamp = entry.TimeGenerated.ToString("o"),
                    Ip = ipAddress,
                    Attempts = attempts,
                    BlockedIp = null,
                };

                Console.WriteLine($"Failed login attempt {attempts} for IP {ipAddress}.");
                await SendDataAsync(eventPayload);
            }
        }

        private static void IncrementFailedLoginAttempt(string ipAddress)
        {
            FailedLoginAttempts.AddOrUpdate(ipAddress, 1, (_, oldValue) => oldValue + 1);
        }

        private static bool IsLocalhost(string ipAddress) =>
            ipAddress == "127.0.0.1" || ipAddress == "::1";

        private static string ExtractIPAddress(string message)
        {
            const string ipPattern = @"(?<=Source Network Address:\s)([^\s]+)";
            var match = Regex.Match(message, ipPattern);
            return match.Success ? match.Value : null;
        }

        private static bool BlockIp(string ipAddress)
        {
            if (IsIpBlocked(ipAddress))
            {
                Console.WriteLine($"IP {ipAddress} is already blocked. Skipping rule creation.");
                return false;
            }

            if (!IPAddress.TryParse(ipAddress, out _))
            {
                Console.WriteLine("Invalid IP address. Not blocking.");
                return false;
            }

            string command = $"netsh advfirewall firewall add rule name=\"Block {ipAddress}\" dir=in action=block remoteip={ipAddress}";
            return ExecuteCommand(command);
        }

        private static bool IsIpBlocked(string ipAddress)
        {
            string checkCommand = $"netsh advfirewall firewall show rule name=all | findstr \"{ipAddress}\"";
            string output = ExecuteCommandWithOutput(checkCommand);
            return !string.IsNullOrEmpty(output);
        }

        private static bool ExecuteCommand(string command)
        {
            try
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo("cmd.exe", "/C " + command)
                    {
                        WindowStyle = ProcessWindowStyle.Hidden,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                    },
                };

                process.Start();
                process.WaitForExit();
                return process.ExitCode == 0;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Command execution failed: {ex.Message}");
                return false;
            }
        }

        private static string ExecuteCommandWithOutput(string command)
        {
            try
            {
                using var process = new Process
                {
                    StartInfo = new ProcessStartInfo("cmd.exe", "/C " + command)
                    {
                        WindowStyle = ProcessWindowStyle.Hidden,
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        RedirectStandardOutput = true,
                    },
                };

                process.Start();
                string output = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                return output;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Command execution with output failed: {ex.Message}");
                return string.Empty;
            }
        }

        private static async Task SendDataAsync(EventPayload payload)
        {
            if (string.IsNullOrEmpty(ApiUrl))
            {
                Console.WriteLine("API URL is not set. Data will not be sent.");
                return;
            }

            try
            {
                string jsonData = JsonConvert.SerializeObject(payload);
                var content = new StringContent(jsonData, Encoding.UTF8, "application/json");
                var response = await HttpClient.PostAsync(ApiUrl, content);

                if (!response.IsSuccessStatusCode)
                {
                    string responseBody = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"POST request failed for event_id {payload.EventId}: {response.StatusCode} - {responseBody}");
                }
                else
                {
                    Console.WriteLine($"POST request successful for event_id {payload.EventId}!");
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"HTTP Request Exception for event_id {payload.EventId}: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception occurred for event_id {payload.EventId}: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private static bool IsApiUrlValid(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            if (Uri.TryCreate(url, UriKind.Absolute, out var uriResult))
            {
                return uriResult.Scheme == Uri.UriSchemeHttp || uriResult.Scheme == Uri.UriSchemeHttps;
            }

            return false;
        }
    }
}
