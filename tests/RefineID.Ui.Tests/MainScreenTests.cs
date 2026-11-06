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
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Definitions;
using Xunit;

/// <summary>
/// The app opens, its main screen is complete and operable without a mouse,
/// and running it reports no failure. One app runs at a time: the tests share
/// the desktop's focus.
/// </summary>
[Collection(nameof(MainScreenTests))]
[CollectionDefinition(nameof(MainScreenTests), DisableParallelization = true)]
public sealed partial class MainScreenTests
{
    /// <summary>The event source every RefineID process reports failures as.</summary>
    private const string EventSource = "RefineID";

    /// <summary>The program name inside an event of the app's own.</summary>
    private const string AppProgram = "RefineID.exe";

    /// <summary>The main screen's cards a holder always has.</summary>
    private const string VerifyCard = "VerifyCard";

    /// <summary>The control only the document page's verify mode shows.</summary>
    private const string VerifyButton = "VerifyButton";

    /// <summary>How long the app runs before it is judged to have stayed up.</summary>
    private static readonly TimeSpan SettleTime = TimeSpan.FromSeconds(5);

    /// <summary>The control types a holder acts on, each of which needs a name.</summary>
    private static readonly ControlType[] ActionableTypes =
    [
        ControlType.Button,
        ControlType.CheckBox,
        ControlType.ComboBox,
        ControlType.Edit,
        ControlType.Hyperlink,
        ControlType.RadioButton,
    ];

    [Fact]
    public void The_app_opens_and_stays_up_without_reporting_a_failure()
    {
        using RunningApp app = new();

        Assert.NotNull(app.Find(VerifyCard));
        Thread.Sleep(SettleTime);

        Assert.True(app.IsRunning, "The app exited on its own.");
        Assert.Empty(ReportedFailures(app.StartedAt));
    }

    [Fact]
    public void The_verify_card_is_operable_through_ui_automation()
    {
        using RunningApp app = new();

        AutomationElement card =
            app.Find(VerifyCard) ?? throw new Xunit.Sdk.XunitException(VerifyCard);

        Assert.True(card.Patterns.Invoke.IsSupported, "No InvokePattern on the card.");
    }

    [Fact]
    public void Invoking_the_verify_card_opens_the_document_page()
    {
        using RunningApp app = new();
        AutomationElement card =
            app.Find(VerifyCard) ?? throw new Xunit.Sdk.XunitException(VerifyCard);

        card.Patterns.Invoke.Pattern.Invoke();

        Assert.NotNull(app.Find(VerifyButton));
        Assert.True(app.IsRunning, "The app exited on its own.");
        Assert.Empty(ReportedFailures(app.StartedAt));
    }

    /// <summary>Takes the pointer: the desktop must be free (doc/testing.md).</summary>
    [Fact]
    public void A_pointer_click_on_the_verify_card_opens_the_document_page()
    {
        using RunningApp app = new();
        AutomationElement card =
            app.Find(VerifyCard) ?? throw new Xunit.Sdk.XunitException(VerifyCard);
        app.Window.SetForeground();
        Assert.Equal(app.Window.Properties.NativeWindowHandle.Value, GetForegroundWindow());

        card.Click();

        Assert.NotNull(app.Find(VerifyButton));
    }

    [Fact]
    public void Every_actionable_control_has_a_name()
    {
        using RunningApp app = new();
        Assert.NotNull(app.Find(VerifyCard));

        var unnamed = app
            .Window.FindAllDescendants()
            .Where(element =>
                ActionableTypes.Contains(element.Properties.ControlType.ValueOrDefault)
            )
            .Where(element => !element.Properties.IsOffscreen.ValueOrDefault)
            .Where(element => string.IsNullOrWhiteSpace(element.Properties.Name.ValueOrDefault))
            .Select(element => element.Properties.AutomationId.ValueOrDefault ?? "(no id)")
            .ToList();

        Assert.Empty(unnamed);
    }

    [LibraryImport("user32.dll")]
    private static partial nint GetForegroundWindow();

    /// <summary>The app's failures in the Application log since the start.</summary>
    private static List<string> ReportedFailures(DateTime since)
    {
        using EventLog log = new("Application");
        return log
            .Entries.Cast<EventLogEntry>()
            .Reverse()
            .TakeWhile(entry => entry.TimeGenerated >= since)
            .Where(entry => entry.Source == EventSource)
            .Where(entry => entry.ReplacementStrings?.Contains(AppProgram) == true)
            .Select(entry => entry.ReplacementStrings[0])
            .ToList();
    }
}
