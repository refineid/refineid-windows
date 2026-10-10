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
/// Finds and disables, without elevation, the inbound Windows Firewall rule earlier
/// releases opened for RAPP.
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
    /// Disables the rule when it is enabled, without elevation. Returns true when
    /// no enabled rule remains. A rule only an administrator can change is left
    /// as it is.
    /// </summary>
    public static bool DisableLegacyRule()
    {
        if (!IsRuleConfigured())
        {
            return true;
        }

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
            return process.HasExited && process.ExitCode == 0;
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
