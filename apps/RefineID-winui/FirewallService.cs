// Copyright 2026 Petri Koistinen
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

namespace RefineID;

using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;

/// <summary>
/// Verifies and configures the Windows Firewall rule for RefineID RAPP remote card sessions.
/// </summary>
internal static class FirewallService
{
    private const string RuleName = "RefineID RAPP";
    private const string PortRange = "40000-60000";

    /// <summary>
    /// Checks whether the inbound firewall rule for RefineID RAPP is configured and enabled.
    /// </summary>
    public static bool IsRuleConfigured()
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall show rule name=\"{RuleName}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(3000);

            if (process.ExitCode != 0)
            {
                return false;
            }

            return output.Contains(RuleName, StringComparison.OrdinalIgnoreCase)
                && (
                    output.Contains("Yes", StringComparison.OrdinalIgnoreCase)
                    || output.Contains("Kyllä", StringComparison.OrdinalIgnoreCase)
                    || output.Contains("Ja", StringComparison.OrdinalIgnoreCase)
                    || output.Contains("Oui", StringComparison.OrdinalIgnoreCase)
                );
        }
        catch (Win32Exception)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// Closes the RAPP firewall rule by disabling inbound connections.
    /// Used when a local smart card is in use or RAPP is not needed.
    /// </summary>
    public static bool CloseRule()
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall set rule name=\"{RuleName}\" new enable=no",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };

            process.Start();
            process.WaitForExit(3000);
            if (process.ExitCode == 0)
            {
                return true;
            }

            using var elevated = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall set rule name=\"{RuleName}\" new enable=no",
                    UseShellExecute = true,
                    Verb = "runas",
                },
            };

            elevated.Start();
            elevated.WaitForExit(5000);
            return elevated.ExitCode == 0;
        }
        catch (Win32Exception)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>
    /// Opens the RAPP firewall rule when remote phone card reader is needed.
    /// Re-enables the rule if already present, or creates it if missing.
    /// </summary>
    public static bool OpenRule()
    {
        if (IsRuleConfigured())
        {
            return true;
        }

        try
        {
            using var enableProcess = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments = $"advfirewall firewall set rule name=\"{RuleName}\" new enable=yes",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                },
            };

            enableProcess.Start();
            enableProcess.WaitForExit(3000);
            if (enableProcess.ExitCode == 0 && IsRuleConfigured())
            {
                return true;
            }
        }
        catch (Win32Exception ex)
        {
            Debug.WriteLine($"Failed to enable firewall rule via netsh: {ex.Message}");
        }
        catch (InvalidOperationException ex)
        {
            Debug.WriteLine($"Failed to enable firewall rule via netsh: {ex.Message}");
        }
        catch (IOException ex)
        {
            Debug.WriteLine($"Failed to enable firewall rule via netsh: {ex.Message}");
        }

        return ConfigureRule();
    }

    /// <summary>
    /// Requests Windows UAC elevation to add the inbound firewall rule.
    /// Returns true if the command executed with exit code 0.
    /// </summary>
    public static bool ConfigureRule()
    {
        try
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "netsh",
                    Arguments =
                        $"advfirewall firewall add rule name=\"{RuleName}\" dir=in action=allow protocol=TCP localport={PortRange}",
                    UseShellExecute = true,
                    Verb = "runas",
                },
            };

            process.Start();
            process.WaitForExit(10000);
            return process.ExitCode == 0;
        }
        catch (Win32Exception)
        {
            return false;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }
}
