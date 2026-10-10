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
/// Finds and disables the inbound Windows Firewall rule earlier releases opened for RAPP.
/// </summary>
internal static class FirewallService
{
    private const string RuleName = "RefineID RAPP";

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
}
