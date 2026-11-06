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

namespace RefineID.Ui.Tests;

using System.Diagnostics;
using System.Runtime.InteropServices;
using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Tools;
using FlaUI.UIA3;

/// <summary>
/// The Debug build of the app, running for one test against an empty profile.
/// </summary>
/// <remarks>
/// <c>LOCALAPPDATA</c> points the app's pairing store at a temporary
/// directory, so a test never sees or changes the user's pairings. A card in
/// a reader is real: a test asserts only what holds with or without one, and
/// enters no secret.
/// </remarks>
internal sealed class RunningApp : IDisposable
{
    /// <summary>How long the first screen may take to appear.</summary>
    internal static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(30);

    /// <summary>How long a control may take to appear after an action.</summary>
    internal static readonly TimeSpan ControlTimeout = TimeSpan.FromSeconds(10);

    private const string AppDirectory = "apps/RefineID-winui/bin";
    private const string AppExecutable = "RefineID.exe";
    private const string RootMarker = "AGENTS.md";
    private const string ProfileVariable = "LOCALAPPDATA";

    private readonly string profile;
    private readonly Application application;
    private readonly UIA3Automation automation = new();

    internal RunningApp()
    {
        // The event log keeps whole seconds.
        DateTime now = DateTime.Now;
        this.StartedAt = now.AddTicks(-(now.Ticks % TimeSpan.TicksPerSecond));
        this.profile = Directory.CreateTempSubdirectory("refineid-ui-test-").FullName;
        ProcessStartInfo start = new(FindExecutable()) { UseShellExecute = false };
        start.Environment[ProfileVariable] = this.profile;
        this.application = Application.Launch(start);
        try
        {
            this.Window =
                this.application.GetMainWindow(this.automation, StartTimeout)
                ?? throw new InvalidOperationException("The main window did not open.");
        }
        catch
        {
            this.Dispose();
            throw;
        }
    }

    /// <summary>When the app was started.</summary>
    internal DateTime StartedAt { get; }

    /// <summary>The app's main window.</summary>
    internal Window Window { get; }

    /// <summary>Whether the app's process is still running.</summary>
    internal bool IsRunning => !this.application.HasExited;

    /// <summary>The control with this automation identifier, once it appears.</summary>
    internal AutomationElement? Find(string automationId) =>
        Retry
            .WhileNull(
                () => this.Window.FindFirstDescendant(match => match.ByAutomationId(automationId)),
                ControlTimeout
            )
            .Result;

    public void Dispose()
    {
        this.automation.Dispose();
        using Process process = Process.GetProcessById(this.application.ProcessId);
        this.application.Kill();
        process.WaitForExit(StartTimeout);
        this.application.Dispose();
        Directory.Delete(this.profile, recursive: true);
    }

    private static string FindExecutable()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, RootMarker)))
        {
            directory = directory.Parent;
        }
        string built = Path.Combine(directory?.FullName ?? "", AppDirectory);
        string architecture = RuntimeInformation.ProcessArchitecture.ToString().ToLowerInvariant();
        return Directory
                .EnumerateFiles(built, AppExecutable, SearchOption.AllDirectories)
                .Where(path => path.Contains("Debug", StringComparison.Ordinal))
                .Where(path => path.Contains($"win-{architecture}", StringComparison.Ordinal))
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault()
            ?? throw new FileNotFoundException("Build the Debug app: scripts/test.ps1 -Tier ui");
    }
}
