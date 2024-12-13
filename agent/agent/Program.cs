using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Agent
{
    class Program
    {
        // Identifier for the machine on which this agent runs
        private const string MachineID = "Win11-Virtual_Machine-- DEMO";

        // Using HTTP URL
        private const string ApiUrl = "http://192.168.1.171:5000/api";

        private static readonly HttpClient HttpClient = new HttpClient();

        private static DateTime _lastSentTime;
        private static readonly object _lastSentTimeLock = new object();

        private static readonly HashSet<int> MonitoredEventIDs = new()
        {
            104,
            106,
            201,
            740,
            741,
            1102,
            1116,
            1118,
            1119,
            1120,
            4624,
            4625,
            4634,
            4647,
            4648,
            4656,
            4672,
            4697,
            4698,
            4699,
            4700,
            4701,
            4702,
            4719,
            4720,
            4722,
            4724,
            4728,
            4732,
            4738,
            4756,
            4768,
            4769,
            4771,
            4776,
            5001,
            5140,
            5142,
            5145,
            5157,
            7034,
            7036,
            7040,
            7045,
        };

        private const int FailedLoginThreshold = 3;
        private static readonly TimeSpan MonitoringWindow = TimeSpan.FromMinutes(15);

        private static readonly ConcurrentDictionary<string, int> FailedLoginAttempts = new();

        static async Task Main()
        {
            lock (_lastSentTimeLock)
            {
                _lastSentTime = DateTime.Now;
            }

            // Verify that the configured API URL is valid and uses HTTP
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
            if (!MonitoredEventIDs.Contains(entry.EventID))
                return;
            if (!IsNewLogEntry(entry))
                return;

            var generalPayload = new
            {
                event_id = entry.EventID,
                machine_id = MachineID,
                category_number = entry.CategoryNumber,
                log_index = entry.Index,
                timestamp = entry.TimeGenerated.ToString("o"),
            };

            await SendDataAsync(generalPayload);

            if (entry.EventID == 4625)
            {
                await HandleFailedLoginAsync(entry);
            }

            lock (_lastSentTimeLock)
            {
                if (entry.TimeGenerated > _lastSentTime)
                {
                    _lastSentTime = entry.TimeGenerated;
                }
            }
        }

        private static bool IsNewLogEntry(EventLogEntry entry)
        {
            lock (_lastSentTimeLock)
            {
                return entry.TimeGenerated > _lastSentTime;
            }
        }

        private static async Task SendDataAsync(object payload)
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
                    Console.WriteLine(
                        $"POST request failed: {response.StatusCode} - {responseBody}"
                    );
                }
                else
                {
                    Console.WriteLine("POST request successful!");
                }
            }
            catch (HttpRequestException ex)
            {
                Console.WriteLine($"HTTP Request Exception: {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception occurred: {ex.Message}\n{ex.StackTrace}");
            }
        }

        private static async Task HandleFailedLoginAsync(EventLogEntry entry)
        {
            string ipAddress = ExtractIPAddress(entry.Message);

            if (string.IsNullOrEmpty(ipAddress) || !IPAddress.TryParse(ipAddress, out _))
            {
                return;
            }

            IncrementFailedLoginAttempt(ipAddress);

            int attempts = FailedLoginAttempts[ipAddress];
            bool shouldBlock = attempts >= FailedLoginThreshold && !IsLocalhost(ipAddress);

            var eventPayload = new
            {
                event_id = 4625,
                machine_id = MachineID,
                category_number = entry.CategoryNumber,
                log_index = entry.Index,
                timestamp = entry.TimeGenerated.ToString("o"),
                ip = ipAddress,
                attempts = attempts,
                blocked_ip = shouldBlock ? ipAddress : null,
            };

            await SendDataAsync(eventPayload);

            if (shouldBlock && BlockIp(ipAddress))
            {
                FailedLoginAttempts[ipAddress] = 0;
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

            string command =
                $"netsh advfirewall firewall add rule name=\"Block {ipAddress}\" dir=in action=block remoteip={ipAddress}";
            return ExecuteCommand(command);
        }

        private static bool IsIpBlocked(string ipAddress)
        {
            string checkCommand =
                $"netsh advfirewall firewall show rule name=all | findstr \"{ipAddress}\"";
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

        /// <summary>
        /// Validates that the provided API URL is a non-empty URL using HTTP.
        /// </summary>
        private static bool IsApiUrlValid(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;

            if (Uri.TryCreate(url, UriKind.Absolute, out var uriResult))
            {
                // Allow only HTTP
                return uriResult.Scheme == Uri.UriSchemeHttp;
            }

            return false;
        }
    }
}
