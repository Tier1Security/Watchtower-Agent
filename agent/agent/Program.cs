using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Agent
{
    /// <summary>
    /// The 10 categories for high-level attacks plus an Unknown fallback.
    /// </summary>
    public enum HighLevelAttackType
    {
        UserCredentialBruteForcing,
        PrivilegeEscalation,
        LateralMovement,
        CredentialDumping,
        Persistence,
        ClearingSecurityLogs,
        RemoteDesktopAttacks,
        UserAccountManipulation,
        FirewallIPSecPolicyChanges,
        TimeTamperingOrSystemIntegrity,
        UnknownOrNotApplicable
    }

    /// <summary>
    /// One raw "low-level" event that the aggregator collects.
    /// </summary>
    public record LowLevelEvent(int EventId, DateTime TimeGenerated, string Message);

    /// <summary>
    /// Aggregator that collects raw events for a single (AttackType, CorrelationKey).
    /// Once some threshold or time condition is reached, we finalize and send one alert.
    /// 
    /// This version includes an example "chain logic" for Privilege Escalation.
    /// </summary>
    public class HighLevelAggregator
    {
        // The category and correlation key for which we are aggregating.
        public HighLevelAttackType AttackType { get; }
        public string CorrelationKey { get; }

        // Collected events
        public List<LowLevelEvent> Events { get; } = new();

        // Has this aggregator been finalized (alert sent)?
        public bool IsComplete { get; private set; }

        // The moment we created this aggregator
        public DateTime CreatedUtc { get; }

        // The moment we last received an event
        public DateTime LastEventUtc { get; private set; }

        // For concurrency, so we don't finalize the same aggregator multiple times
        private readonly object aggregatorLock = new();

        // EXAMPLE: For a multi-step sequence in "Privilege Escalation"
        //  - step 1 means we've seen 4672
        //  - step 2 means we've seen 4672 then 4673
        //  - step 3 means we've seen 4672, 4673, then 4674 => finalize
        private int _privEscalationStep = 0;

        public HighLevelAggregator(HighLevelAttackType attackType, string correlationKey)
        {
            AttackType = attackType;
            CorrelationKey = correlationKey;
            CreatedUtc = DateTime.UtcNow;
            LastEventUtc = CreatedUtc;
        }

        /// <summary>
        /// Add a new event. Return true if we decided to finalize now.
        /// </summary>
        public bool AddEvent(int eventId, DateTime eventTime, string message)
        {
            lock (aggregatorLock)
            {
                if (IsComplete) 
                    return false;

                Events.Add(new LowLevelEvent(eventId, eventTime, message));
                LastEventUtc = DateTime.UtcNow;

                // Decide if we should finalize *right now* based on the category logic
                return ShouldFinalize(eventId, message);
            }
        }

        /// <summary>
        /// This method checks (1) threshold logic, (2) chain logic, (3) single-event triggers, etc.
        /// If the aggregator should finalize, set IsComplete=true and return true.
        /// Otherwise return false.
        /// 
        /// Below are examples for:
        ///  - User Credential Brute Forcing
        ///  - Privilege Escalation (multi-step chain example)
        ///  - Clearing Security Logs
        ///  - Remote Desktop Attacks
        ///  - Time Tampering or Single-Event detection
        /// </summary>
        private bool ShouldFinalize(int latestEventId, string message)
        {
            switch (AttackType)
            {
                case HighLevelAttackType.UserCredentialBruteForcing:
                {
                    // If we see an account lockout (4740), finalize
                    if (latestEventId == 4740)
                    {
                        IsComplete = true;
                        return true;
                    }
                    // Or if we see 10 x 4625 in <= 2 minutes
                    int failCount = 0;
                    foreach (var e in Events)
                    {
                        if (e.EventId == 4625)
                            failCount++;
                    }
                    if (failCount >= 10 && (DateTime.UtcNow - CreatedUtc).TotalMinutes <= 2)
                    {
                        IsComplete = true;
                        return true;
                    }
                    break;
                }

                case HighLevelAttackType.PrivilegeEscalation:
                {
                    // *** Multi-step chain example ***
                    // We want to see 4672 -> 4673 -> 4674 in that order, within 5 minutes (arbitrary).
                    // If we reach step 3, we finalize.

                    // (1) If we see 4672 and we haven't started the chain, move step to 1
                    if (latestEventId == 4672 && _privEscalationStep == 0)
                    {
                        _privEscalationStep = 1;
                    }
                    // (2) If we see 4673 and the chain step is 1, move to step 2
                    else if (latestEventId == 4673 && _privEscalationStep == 1)
                    {
                        _privEscalationStep = 2;
                    }
                    // (3) If we see 4674 and the chain step is 2 => finalize
                    else if (latestEventId == 4674 && _privEscalationStep == 2)
                    {
                        // also check if the chain happened within 5 minutes of aggregator creation
                        if ((DateTime.UtcNow - CreatedUtc).TotalMinutes <= 5)
                        {
                            IsComplete = true;
                            return true;
                        }
                        else
                        {
                            // If it took more than 5 minutes, you can choose to finalize anyway,
                            // or ignore. For this example, let's finalize anyway:
                            IsComplete = true;
                            return true;
                        }
                    }
                    break;
                }

                case HighLevelAttackType.ClearingSecurityLogs:
                {
                    // If 1102 or 1100 => finalize immediately
                    if (latestEventId == 1102 || latestEventId == 1100)
                    {
                        IsComplete = true;
                        return true;
                    }
                    break;
                }

                case HighLevelAttackType.RemoteDesktopAttacks:
                {
                    // E.g. if 3 consecutive 4625 with "Logon Type: 10" in < 2 min
                    int rdpFails = 0;
                    foreach (var ev in Events)
                    {
                        if (ev.EventId == 4625 && ev.Message.Contains("Logon Type: 10"))
                            rdpFails++;
                    }
                    if (rdpFails >= 3 && (DateTime.UtcNow - CreatedUtc).TotalMinutes <= 2)
                    {
                        IsComplete = true;
                        return true;
                    }
                    break;
                }

                case HighLevelAttackType.TimeTamperingOrSystemIntegrity:
                {
                    // For simplicity, finalize on the first event
                    IsComplete = true;
                    return true;
                }

                default:
                    // For other categories, you might add other chain logic or finalize rules
                    break;
            }

            return false;
        }

        /// <summary>
        /// Force finalization, e.g. if aggregator is stale or a time limit is reached,
        /// even if we haven't triggered "ShouldFinalize" from a direct event.
        /// </summary>
        public bool ForceFinalize()
        {
            lock (aggregatorLock)
            {
                if (IsComplete)
                    return false;

                IsComplete = true;
                return true;
            }
        }
    }

    /// <summary>
    /// The final alert payload representing a single high-level attack with multiple low-level events.
    /// </summary>
    public class HighLevelAlertPayload
    {
        [JsonProperty("license")]
        public string License { get; set; }

        [JsonProperty("high_level_event")]
        public string HighLevelEvent { get; set; }

        [JsonProperty("correlation_key")]
        public string CorrelationKey { get; set; }

        [JsonProperty("event_count")]
        public int EventCount { get; set; }

        [JsonProperty("events")]
        public List<LowLevelAlert> Events { get; set; } = new();
    }

    /// <summary>
    /// One low-level event within the final aggregator alert, truncated for readability.
    /// </summary>
    public class LowLevelAlert
    {
        [JsonProperty("event_id")]
        public int EventId { get; set; }

        [JsonProperty("time")]
        public string Time { get; set; }

        [JsonProperty("message_snippet")]
        public string MessageSnippet { get; set; }
    }

    /// <summary>
    /// Manages aggregator objects, keyed by (AttackType, correlationKey).
    /// Also does periodic cleanup of stale aggregators.
    /// 
    /// Includes a chain-based aggregator approach for "Privilege Escalation" 
    /// as an example. You can add more chain logic for other categories similarly.
    /// </summary>
    public static class HighLevelAttackManager
    {
        // Key = (AttackType, correlationKey)
        private static readonly ConcurrentDictionary<(HighLevelAttackType, string), HighLevelAggregator> Aggregators
            = new();

        private static Timer cleanupTimer;

        // How often we run aggregator cleanup
        private static readonly TimeSpan CleanupInterval = TimeSpan.FromMinutes(1);

        // How long we wait before finalizing or discarding aggregator if no new events
        private static readonly TimeSpan MaxAggregatorLifetime = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Initialize the cleanup timer once. Call this e.g. from Program.Main.
        /// </summary>
        public static void StartCleanupTimer()
        {
            cleanupTimer = new Timer(_ => CleanupStaleAggregators(), null, CleanupInterval, CleanupInterval);
        }

        /// <summary>
        /// Stop the cleanup timer if needed. For graceful shutdown.
        /// </summary>
        public static void StopCleanupTimer()
        {
            cleanupTimer?.Dispose();
        }

        /// <summary>
        /// Primary entry point to handle a new event. 
        /// 1) Retrieve or create aggregator for (attackType, correlationKey). 
        /// 2) Add the event. 
        /// 3) If aggregator finalizes, we send one alert and remove it.
        /// </summary>
        public static async Task HandleEventAsync(
            HighLevelAttackType attackType,
            string correlationKey,
            int eventId,
            DateTime eventTime,
            string message)
        {
            if (attackType == HighLevelAttackType.UnknownOrNotApplicable)
            {
                // We skip events that do not map to the 10 recognized categories
                return;
            }

            var aggregator = Aggregators.GetOrAdd(
                (attackType, correlationKey),
                _ => new HighLevelAggregator(attackType, correlationKey));

            bool aggregatorIsComplete = aggregator.AddEvent(eventId, eventTime, message);

            if (aggregatorIsComplete)
            {
                await FinalizeAndRemoveAggregator((attackType, correlationKey));
            }
        }

        /// <summary>
        /// Checks all aggregators for staleness (no new events after X minutes).
        /// If stale, finalize or optionally discard them.
        /// </summary>
        private static void CleanupStaleAggregators()
        {
            foreach (var kvp in Aggregators)
            {
                var key = kvp.Key;
                var aggregator = kvp.Value;

                if (aggregator.IsComplete)
                {
                    // Already done, just remove if it wasn't removed for some reason
                    Aggregators.TryRemove(key, out _);
                    continue;
                }

                // If aggregator is older than MaxAggregatorLifetime with no new events,
                // we finalize it. Or you can choose to discard it if you prefer.
                if (DateTime.UtcNow - aggregator.LastEventUtc > MaxAggregatorLifetime)
                {
                    bool forced = aggregator.ForceFinalize();
                    if (forced)
                    {
                        // aggregator was not yet complete, so now we finalize
                        _ = FinalizeAndRemoveAggregator(key); 
                        // We can discard the Task because finalization is asynchronous
                    }
                    else
                    {
                        // aggregator was already complete or forcibly completed by something else
                        Aggregators.TryRemove(key, out _);
                    }
                }
            }
        }

        /// <summary>
        /// Finalize aggregator => build alert => send => remove from dictionary.
        /// </summary>
        private static async Task FinalizeAndRemoveAggregator((HighLevelAttackType, string) key)
        {
            if (!Aggregators.TryGetValue(key, out var aggregator))
                return; // race condition: aggregator might have been removed

            var payload = BuildHighLevelAlertPayload(aggregator);
            await SendAggregatedAlertAsync(payload);

            // remove aggregator from dictionary
            Aggregators.TryRemove(key, out _);
        }

        private static HighLevelAlertPayload BuildHighLevelAlertPayload(HighLevelAggregator aggregator)
        {
            var payload = new HighLevelAlertPayload
            {
                License        = Program.license,
                HighLevelEvent = aggregator.AttackType.ToString(),
                CorrelationKey = aggregator.CorrelationKey,
                EventCount     = aggregator.Events.Count
            };

            foreach (var e in aggregator.Events)
            {
                payload.Events.Add(new LowLevelAlert
                {
                    EventId = e.EventId,
                    Time    = e.TimeGenerated.ToString("o"),
                    MessageSnippet = e.Message.Length > 100
                        ? e.Message[..100] + "..."
                        : e.Message
                });
            }

            return payload;
        }

        private static async Task SendAggregatedAlertAsync(HighLevelAlertPayload payload)
        {
            if (string.IsNullOrEmpty(Program.ApiUrl))
            {
                Console.WriteLine("API URL not set. Cannot send aggregator alert.");
                return;
            }

            try
            {
                string jsonData = JsonConvert.SerializeObject(payload);
                using var content = new StringContent(jsonData, Encoding.UTF8, "application/json");

                var response = await Program.HttpClient.PostAsync(Program.ApiUrl, content);
                if (!response.IsSuccessStatusCode)
                {
                    string resp = await response.Content.ReadAsStringAsync();
                    Console.WriteLine($"[ERROR] POST aggregator alert failed: {resp}");
                }
                else
                {
                    Console.WriteLine($"[ALERT SENT] {payload.HighLevelEvent}, " +
                                      $"Key={payload.CorrelationKey}, " +
                                      $"Count={payload.EventCount}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Exception sending aggregator alert: {ex.Message}");
            }
        }
    }

    /// <summary>
    /// The main Program that listens to Windows Security logs, only processes recognized events,
    /// and uses the HighLevelAttackManager to handle aggregator logic (including chain logic).
    /// </summary>
    public class Program
    {
        // *** CONFIG: Your license key, your API endpoint, etc. ***
        public const string license = "<LICENSE_KEY>";
        public const string ApiUrl = "https://www.tier1security.org/api";

        public static readonly HttpClient HttpClient = new HttpClient();
        private static DateTime ProgramStartTime;

        private static readonly object LogHashLock = new();
        private static readonly HashSet<string> ProcessedLogHashes = new();

        // This dictionary helps us quickly identify if an event ID might belong to one of the 10 categories
        // (except for special logic like "4625 with Logon Type: 10" => RemoteDesktopAttacks).
        private static readonly Dictionary<int, HighLevelAttackType> SimpleEventIdMap = new()
        {
            // 1) User Credential Brute Forcing
            { 4625, HighLevelAttackType.UserCredentialBruteForcing },
            { 4740, HighLevelAttackType.UserCredentialBruteForcing },
            { 4771, HighLevelAttackType.UserCredentialBruteForcing },

            // 2) Privilege Escalation
            { 4672, HighLevelAttackType.PrivilegeEscalation },
            { 4673, HighLevelAttackType.PrivilegeEscalation },
            { 4674, HighLevelAttackType.PrivilegeEscalation },
            { 4697, HighLevelAttackType.PrivilegeEscalation },
            { 4728, HighLevelAttackType.PrivilegeEscalation },
            { 4732, HighLevelAttackType.PrivilegeEscalation },
            { 4756, HighLevelAttackType.PrivilegeEscalation },

            // 3) Lateral Movement
            { 4624, HighLevelAttackType.LateralMovement },
            { 5140, HighLevelAttackType.LateralMovement },
            { 5145, HighLevelAttackType.LateralMovement },

            // 4) Credential Dumping
            { 4688, HighLevelAttackType.CredentialDumping },
            { 4663, HighLevelAttackType.CredentialDumping },
            { 4656, HighLevelAttackType.CredentialDumping },
            { 4658, HighLevelAttackType.CredentialDumping },

            // 5) Persistence
            { 4698, HighLevelAttackType.Persistence },
            { 4699, HighLevelAttackType.Persistence },
            { 4702, HighLevelAttackType.Persistence },
            { 7045, HighLevelAttackType.Persistence },

            // 6) Clearing Security Logs
            { 1102, HighLevelAttackType.ClearingSecurityLogs },
            { 1100, HighLevelAttackType.ClearingSecurityLogs },

            // 7) Remote Desktop Attacks
            // (4625 or 4624 can also become RemoteDesktopAttacks if "Logon Type: 10" => see special check)
            { 4825, HighLevelAttackType.RemoteDesktopAttacks },

            // 8) User Account Manipulation
            { 4720, HighLevelAttackType.UserAccountManipulation },
            { 4722, HighLevelAttackType.UserAccountManipulation },
            { 4723, HighLevelAttackType.UserAccountManipulation },
            { 4724, HighLevelAttackType.UserAccountManipulation },
            { 4725, HighLevelAttackType.UserAccountManipulation },

            // 9) Firewall / IPSec
            { 4946, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 4947, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 4948, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 5050, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 5051, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 5056, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 5057, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 5025, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 5026, HighLevelAttackType.FirewallIPSecPolicyChanges },
            { 5027, HighLevelAttackType.FirewallIPSecPolicyChanges },

            // 10) Time Tampering / System Integrity
            { 4616, HighLevelAttackType.TimeTamperingOrSystemIntegrity },
            { 5038, HighLevelAttackType.TimeTamperingOrSystemIntegrity },
            { 5039, HighLevelAttackType.TimeTamperingOrSystemIntegrity },
            { 6281, HighLevelAttackType.TimeTamperingOrSystemIntegrity }
        };

        // Any Windows Security events you want to watch
        // (only those that might appear in your 10 categories or have special logic).
        private static readonly HashSet<int> MonitoredEventIDs = new()
        {
            4624, 4625, 4740, 4771,
            4672, 4673, 4674, 4697, 4728, 4732, 4756,
            5140, 5145,
            4688, 4663, 4656, 4658,
            4698, 4699, 4702, 7045,
            1100, 1102,
            4825,
            4720, 4722, 4723, 4724, 4725,
            4946, 4947, 4948, 5050, 5051, 5056, 5057, 5025, 5026, 5027,
            4616, 5038, 5039, 6281
        };

        public static async Task Main()
        {
            ProgramStartTime = DateTime.Now;

            // Start aggregator cleanup in the background
            HighLevelAttackManager.StartCleanupTimer();

            // Validate API
            if (!IsApiUrlValid(ApiUrl))
            {
                Console.WriteLine("API URL is not properly set. Exiting...");
                return;
            }

            // Start reading the Security event log
            await StartEventParsingAsync();

            // Optionally, if you want a graceful shutdown, stop the timer
            HighLevelAttackManager.StopCleanupTimer();
        }

        private static async Task StartEventParsingAsync()
        {
            using var eventLog = new EventLog("Security")
            {
                EnableRaisingEvents = true
            };

            eventLog.EntryWritten += async (sender, args) =>
            {
                await ProcessEventLogAsync(args.Entry);
            };

            Console.WriteLine("Monitoring Security event logs. Press any key to exit...");
            await Task.Run(() => Console.ReadKey());
        }

        private static async Task ProcessEventLogAsync(EventLogEntry entry)
        {
            // Skip events before program start
            if (entry.TimeGenerated < ProgramStartTime)
                return;

            // Skip if not in the monitored set
            if (!MonitoredEventIDs.Contains(entry.EventID))
                return;

            // Skip duplicates
            if (IsDuplicateLog(entry))
                return;

            // Identify the high-level category
            var category = DetermineCategory(entry.EventID, entry.Message);
            if (category == HighLevelAttackType.UnknownOrNotApplicable)
            {
                // We skip events that do not map to the 10 recognized categories
                return;
            }

            // Build correlation key (e.g. user or IP)
            string correlationKey = ComputeCorrelationKey(category, entry);

            // Pass to aggregator manager
            await HighLevelAttackManager.HandleEventAsync(
                category,
                correlationKey,
                entry.EventID,
                entry.TimeGenerated,
                entry.Message
            );
        }

        /// <summary>
        /// Deduplicate logs by hashing the combination of index/time/EventID/message.
        /// </summary>
        private static bool IsDuplicateLog(EventLogEntry entry)
        {
            string hash = ComputeLogHash(entry);
            lock (LogHashLock)
            {
                if (ProcessedLogHashes.Contains(hash))
                    return true;

                ProcessedLogHashes.Add(hash);
                if (ProcessedLogHashes.Count > 5000)
                {
                    // Simple memory control: clear if large
                    ProcessedLogHashes.Clear();
                }
            }
            return false;
        }

        private static string ComputeLogHash(EventLogEntry entry)
        {
            using var sha256 = SHA256.Create();
            string raw = $"{entry.Index}-{entry.TimeGenerated}-{entry.EventID}-{entry.Message}";
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(raw));
            return Convert.ToBase64String(bytes);
        }

        /// <summary>
        /// Decide which category an event belongs to, including special logic for 4624/4625 with "Logon Type: 10".
        /// </summary>
        private static HighLevelAttackType DetermineCategory(int eventId, string message)
        {
            // Overlap logic: 4625 or 4624 might be remote desktop if "Logon Type: 10" is in the message
            if ((eventId == 4625 || eventId == 4624) && message.Contains("Logon Type: 10"))
            {
                return HighLevelAttackType.RemoteDesktopAttacks;
            }

            // Otherwise, see if it's in our dictionary
            if (SimpleEventIdMap.TryGetValue(eventId, out var cat))
                return cat;

            return HighLevelAttackType.UnknownOrNotApplicable;
        }

        /// <summary>
        /// For each category, decide how we want to group events (by user, by IP, etc.).
        /// </summary>
        private static string ComputeCorrelationKey(HighLevelAttackType category, EventLogEntry entry)
        {
            switch (category)
            {
                case HighLevelAttackType.UserCredentialBruteForcing:
                {
                    // Possibly correlate by target user
                    var user = ExtractUserName(entry.Message);
                    return string.IsNullOrEmpty(user) ? "unknown_user" : user;
                }
                case HighLevelAttackType.RemoteDesktopAttacks:
                {
                    // Possibly correlate by IP
                    var ip = ExtractIPAddress(entry.Message);
                    return string.IsNullOrEmpty(ip) ? "unknown_ip" : ip;
                }
                case HighLevelAttackType.PrivilegeEscalation:
                {
                    // Possibly correlate by user
                    var user = ExtractUserName(entry.Message);
                    return string.IsNullOrEmpty(user) ? "unknown_user" : user;
                }
                default:
                {
                    // Some fallback
                    return "generic_key";
                }
            }
        }

        private static string ExtractUserName(string message)
        {
            // Rough example. Adjust as needed for your environment.
            var match = Regex.Match(message, @"Account Name:\s+(.+)");
            return match.Success ? match.Groups[1].Value.Trim() : null;
        }

        private static string ExtractIPAddress(string message)
        {
            // Example pattern from your original code
            const string ipPattern = @"(?<=Source Network Address:\s)([^\s]+)";
            var match = Regex.Match(message, ipPattern);
            return match.Success ? match.Value : null;
        }

        private static bool IsApiUrlValid(string url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return false;
            if (Uri.TryCreate(url, UriKind.Absolute, out var uriResult))
            {
                return (uriResult.Scheme == Uri.UriSchemeHttp ||
                        uriResult.Scheme == Uri.UriSchemeHttps);
            }
            return false;
        }
    }
}
