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
    /// <summary>
    /// Represents the payload structure for sending event data to the remote API.
    /// </summary>
    public class EventPayload
    {
        /// <summary>
        /// Gets or sets the ID of the event.
        /// </summary>
        [JsonProperty("event_id")]
        public int EventId { get; set; }

        /// <summary>
        /// Gets or sets the license key associated with the event.
        /// </summary>
        [JsonProperty("license")]
        public string License { get; set; }

        /// <summary>
        /// Gets or sets the category number of the event.
        /// </summary>
        [JsonProperty("category_number")]
        public int CategoryNumber { get; set; }

        /// <summary>
        /// Gets or sets the index (sequence number) of the log in the event log.
        /// </summary>
        [JsonProperty("log_index")]
        public int LogIndex { get; set; }

        /// <summary>
        /// Gets or sets the timestamp of the event in ISO 8601 format.
        /// </summary>
        [JsonProperty("timestamp")]
        public string Timestamp { get; set; }

        /// <summary>
        /// Gets or sets the IP address associated with the event.
        /// </summary>
        [JsonProperty("ip")]
        public string Ip { get; set; }

        /// <summary>
        /// Gets or sets the number of failed login attempts associated with this IP address.
        /// </summary>
        [JsonProperty("attempts")]
        public int Attempts { get; set; }

        /// <summary>
        /// Gets or sets the IP address that was blocked, if any.
        /// </summary>
        [JsonProperty("blocked_ip")]
        public string? BlockedIp { get; set; }
    }

    /// <summary>
    /// Program class containing the main entry point and logic for monitoring Windows Security Event Logs.
    /// </summary>
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

        /// <summary>
        /// The main entry point for the program. Checks the API URL validity and initiates event parsing if valid.
        /// </summary>
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

        /// <summary>
        /// Starts monitoring the Windows Security Event Log asynchronously and waits for user input to exit.
        /// </summary>
        private static async Task StartEventParsingAsync()
        {
            using var eventLog = new EventLog("Security") { EnableRaisingEvents = true };

            eventLog.EntryWritten += async (sender, e) => await ProcessEventLogAsync(e.Entry);

            Console.WriteLine("Monitoring Security event logs. Press any key to exit...");
            await Task.Run(() => Console.ReadKey());
        }

        /// <summary>
        /// Processes an individual EventLogEntry. Filters old events, checks for duplicates, and sends data if necessary.
        /// </summary>
        /// <param name="entry">The event log entry to process.</param>
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

            // Handle non-failed login events immediately
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

            // Handle failed login events (EventID 4625)
            if (entry.EventID == 4625)
            {
                await HandleFailedLoginAsync(entry);
            }
        }

        /// <summary>
        /// Checks if the given event log entry was already processed by comparing a computed hash of its contents.
        /// </summary>
        /// <param name="entry">The event log entry to check.</param>
        /// <returns>True if the log has already been processed, false otherwise.</returns>
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

        /// <summary>
        /// Computes a SHA-256 hash for the event log entry.
        /// </summary>
        /// <param name="entry">The event log entry for which to compute the hash.</param>
        /// <returns>A Base64 string representation of the event log hash.</returns>
        private static string ComputeLogHash(EventLogEntry entry)
        {
            using var sha256 = SHA256.Create();
            string logData = $"{entry.Index}-{entry.TimeGenerated}-{entry.EventID}-{entry.Message}";
            byte[] hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(logData));
            return Convert.ToBase64String(hashBytes);
        }

        /// <summary>
        /// Handles a failed login event by extracting the IP, incrementing its failed count, and optionally blocking it.
        /// </summary>
        /// <param name="entry">The failed login event log entry.</param>
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

        /// <summary>
        /// Increments the failed login attempt count for the specified IP address.
        /// </summary>
        /// <param name="ipAddress">The IP address for which to increment the failed attempt count.</param>
        private static void IncrementFailedLoginAttempt(string ipAddress)
        {
            FailedLoginAttempts.AddOrUpdate(ipAddress, 1, (_, oldValue) => oldValue + 1);
        }

        /// <summary>
        /// Checks if the given IP address is a localhost address.
        /// </summary>
        /// <param name="ipAddress">The IP address to check.</param>
        /// <returns>True if the IP address is localhost, false otherwise.</returns>
        private static bool IsLocalhost(string ipAddress) =>
            ipAddress == "127.0.0.1" || ipAddress == "::1";

        /// <summary>
        /// Extracts an IP address from the event message using a regular expression.
        /// </summary>
        /// <param name="message">The message from which to extract the IP address.</param>
        /// <returns>The extracted IP address, or null if none was found.</returns>
        private static string ExtractIPAddress(string message)
        {
            const string ipPattern = @"(?<=Source Network Address:\s)([^\s]+)";
            var match = Regex.Match(message, ipPattern);
            return match.Success ? match.Value : null;
        }

        /// <summary>
        /// Blocks the specified IP address using Windows Firewall rules, if it is not already blocked.
        /// </summary>
        /// <param name="ipAddress">The IP address to block.</param>
        /// <returns>True if the IP was successfully blocked, false otherwise.</returns>
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

        /// <summary>
        /// Checks whether the given IP address is already blocked by querying Windows Firewall rules.
        /// </summary>
        /// <param name="ipAddress">The IP address to check.</param>
        /// <returns>True if the IP address is already blocked, false otherwise.</returns>
        private static bool IsIpBlocked(string ipAddress)
        {
            string checkCommand = $"netsh advfirewall firewall show rule name=all | findstr \"{ipAddress}\"";
            string output = ExecuteCommandWithOutput(checkCommand);
            return !string.IsNullOrEmpty(output);
        }

        /// <summary>
        /// Executes a command silently using cmd.exe without capturing output.
        /// </summary>
        /// <param name="command">The command to execute.</param>
        /// <returns>True if the command executed successfully, false otherwise.</returns>
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

        /// <summary>
        /// Executes a command silently using cmd.exe and captures the standard output.
        /// </summary>
        /// <param name="command">The command to execute.</param>
        /// <returns>The standard output from the command, or an empty string if an error occurred.</returns>
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

        /// <summary>
        /// Sends event data asynchronously to the configured API endpoint.
        /// </summary>
        /// <param name="payload">The event payload to send.</param>
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

        /// <summary>
        /// Checks if the provided URL is valid (non-empty, well-formed, and uses HTTP or HTTPS).
        /// </summary>
        /// <param name="url">The API URL to validate.</param>
        /// <returns>True if the URL is valid, false otherwise.</returns>
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
