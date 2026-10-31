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

#if DEBUG
namespace RefineID;

using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Text;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;

/// <summary>
/// One entry of the Log window: when it was last written, by which
/// program, what, and how many times in a row.
/// </summary>
internal sealed record DevErrorEntry(
    DateTimeOffset Time,
    string Program,
    string Message,
    int Occurrences
)
{
    /// <summary>The message, with how many times in a row it came.</summary>
    internal string Text =>
        this.Occurrences > 1
            ? string.Create(CultureInfo.InvariantCulture, $"{this.Message} (x{this.Occurrences})")
            : this.Message;

    /// <summary>Whether <paramref name="other"/> is the same failure from the same program.</summary>
    internal bool Repeats(DevErrorEntry other) =>
        string.Equals(this.Program, other.Program, StringComparison.Ordinal)
        && string.Equals(this.Message, other.Message, StringComparison.Ordinal);
}

/// <summary>
/// The development build's Log window: every RefineID error the Windows
/// Event Log holds, from this app and from every other process that runs
/// RefineID code, newest first, as they arrive.
/// </summary>
/// <remarks>
/// A floating window of its own, always on top and movable. It comes up by
/// itself, without taking the keyboard, when an error newer than any shown
/// arrives, and stays until the developer closes it; Ctrl+Shift+E or the
/// version line opens it again. Consecutive repeats of one failure fold
/// into one line with their count. Clear hides every entry up to now, also
/// for later launches; the Application log itself is never cleared. Release
/// builds compile none of this.
/// </remarks>
internal sealed partial class DevErrorWindow : Window
{
    /// <summary>The window's title.</summary>
    private const string WindowTitle = "RefineID - Log";

    /// <summary>How many entries the window keeps; the oldest go first.</summary>
    private const int Capacity = 50;

    /// <summary>The query for every RefineID entry in the Application log.</summary>
    private const string ProviderQuery = "*[System[Provider[@Name='RefineID']]]";

    /// <summary>The log RefineID writes to.</summary>
    private const string LogName = "Application";

    /// <summary>The event log's time format inside an XPath query.</summary>
    private const string QueryTimeFormat = "yyyy-MM-ddTHH:mm:ss.fffZ";

    /// <summary>The file the moment of the last Clear is kept in, under the app's local data.</summary>
    private const string ClearedFileName = "dev-errors-cleared";

    /// <summary>The window's size when it first opens, in pixels.</summary>
    private static readonly SizeInt32 InitialSize = new(820, 320);

    /// <summary>
    /// The main window the log sits beside: at its right edge, or its
    /// left when the right has no room, as tall as it is. The log follows
    /// it until the developer drags the log somewhere else.
    /// </summary>
    private static AppWindow? anchor;

    private static DevErrorWindow? shared;

    /// <summary>Follows the Event Log for new entries while the app runs.</summary>
    private static EventLogWatcher? watcher;

    private readonly DispatcherQueue dispatcher;
    private readonly StackPanel rows = new() { Spacing = 6, Padding = new Thickness(12) };
    private readonly List<DevErrorEntry> entries = [];
    private bool shuttingDown;

    /// <summary>Whether the log still sits where it was put beside the main window.</summary>
    private bool glued = true;

    /// <summary>Where the log was last put beside the main window.</summary>
    private PointInt32 gluedPosition;

    private DevErrorWindow()
    {
        this.dispatcher = DispatcherQueue.GetForCurrentThread();
        this.Title = WindowTitle;

        Button copyAll = new() { Content = "Copy All" };
        copyAll.Click += (sender, args) => this.CopyAll();
        Button clear = new() { Content = "Clear" };
        clear.Click += (sender, args) => this.Clear();
        StackPanel actions = new()
        {
            Orientation = Orientation.Horizontal,
            Spacing = 8,
            HorizontalAlignment = HorizontalAlignment.Right,
            Padding = new Thickness(12, 8, 12, 0),
        };
        actions.Children.Add(copyAll);
        actions.Children.Add(clear);

        ScrollViewer scroller = new() { Content = this.rows };
        Grid.SetRow(scroller, 1);
        Grid root = new()
        {
            Background = (Brush)
                Application.Current.Resources["ApplicationPageBackgroundThemeBrush"],
        };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(
            new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }
        );
        root.Children.Add(actions);
        root.Children.Add(scroller);
        this.Content = root;

        this.AppWindow.Resize(InitialSize);
        if (this.AppWindow.Presenter is OverlappedPresenter presenter)
        {
            presenter.IsAlwaysOnTop = true;
        }

        this.AppWindow.Closing += this.OnClosing;
        this.AppWindow.Changed += this.OnChanged;
    }

    /// <summary>
    /// Starts following the Event Log, once per process: the entries since
    /// the last Clear, then each new one as it is written. The log is
    /// shown beside <paramref name="beside"/>, the main window.
    /// </summary>
    internal static void Start(AppWindow beside)
    {
        if (shared is not null)
        {
            return;
        }

        anchor = beside;
        shared = new DevErrorWindow();
        anchor.Changed += shared.OnAnchorChanged;
        shared.Follow();
    }

    /// <summary>The main window moved or grew; a glued log goes with it.</summary>
    private void OnAnchorChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (this.glued && (args.DidPositionChange || args.DidSizeChange))
        {
            this.SitBeside();
        }
    }

    /// <summary>A move the log did not make itself is the developer taking it apart.</summary>
    private void OnChanged(AppWindow sender, AppWindowChangedEventArgs args)
    {
        if (
            args.DidPositionChange
            && (
                sender.Position.X != this.gluedPosition.X
                || sender.Position.Y != this.gluedPosition.Y
            )
        )
        {
            this.glued = false;
        }
    }

    /// <summary>
    /// Puts the log at the main window's right edge, as tall as the main
    /// window, or at its left edge when the work area has no room on the
    /// right.
    /// </summary>
    private void SitBeside()
    {
        if (anchor is null)
        {
            return;
        }

        RectInt32 work = DisplayArea
            .GetFromWindowId(anchor.Id, DisplayAreaFallback.Nearest)
            .WorkArea;
        int width = this.AppWindow.Size.Width;
        int right = anchor.Position.X + anchor.Size.Width;
        int x;
        if (right + width <= work.X + work.Width)
        {
            x = right;
        }
        else if (anchor.Position.X - width >= work.X)
        {
            x = anchor.Position.X - width;
        }
        else
        {
            // No room on either side: the log keeps to the work area's
            // right edge, over the main window's edge if it must.
            x = work.X + work.Width - width;
        }

        this.gluedPosition = new PointInt32(x, anchor.Position.Y);
        this.AppWindow.MoveAndResize(
            new RectInt32(x, anchor.Position.Y, width, anchor.Size.Height)
        );
    }

    /// <summary>Opens the window for the keyboard.</summary>
    internal static void ShowWindow()
    {
        if (shared is null)
        {
            return;
        }

        shared.Place();
        shared.AppWindow.Show(true);
    }

    /// <summary>A glued log takes its place beside the main window before it shows.</summary>
    private void Place()
    {
        if (this.glued)
        {
            this.SitBeside();
        }
    }

    /// <summary>Closes the window for good, as the app ends.</summary>
    internal static void Shutdown()
    {
        if (shared is null)
        {
            return;
        }

        shared.shuttingDown = true;
        watcher?.Dispose();
        watcher = null;
        shared.Close();
        shared = null;
    }

    private static string ClearedFilePath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "RefineID",
            ClearedFileName
        );

    /// <summary>The moment of the last Clear, or the earliest time when none was kept.</summary>
    private static DateTimeOffset ClearedAt()
    {
        try
        {
            string text = File.ReadAllText(ClearedFilePath).Trim();
            return DateTimeOffset.TryParse(
                text,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind,
                out DateTimeOffset cleared
            )
                ? cleared
                : DateTimeOffset.MinValue;
        }
        catch (IOException)
        {
            return DateTimeOffset.MinValue;
        }
        catch (UnauthorizedAccessException)
        {
            return DateTimeOffset.MinValue;
        }
    }

    /// <summary>Keeps <paramref name="moment"/> as the moment of the last Clear.</summary>
    private static void KeepClearedAt(DateTimeOffset moment)
    {
        try
        {
            _ = Directory.CreateDirectory(Path.GetDirectoryName(ClearedFilePath)!);
            File.WriteAllText(ClearedFilePath, moment.ToString("O", CultureInfo.InvariantCulture));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>The entry an Event Log record carries, or null when it carries none.</summary>
    private static DevErrorEntry? EntryOf(EventRecord record)
    {
        IList<EventProperty> properties = record.Properties;
        if (properties.Count == 0 || properties[0].Value is not string message)
        {
            return null;
        }

        string program = properties.Count > 1 && properties[1].Value is string name ? name : "";
        int occurrences =
            properties.Count > 2
            && properties[2].Value is string count
            && int.TryParse(count, NumberStyles.None, CultureInfo.InvariantCulture, out int parsed)
            && parsed > 0
                ? parsed
                : 1;
        DateTimeOffset time = record.TimeCreated is DateTime created
            ? new DateTimeOffset(created.ToUniversalTime(), TimeSpan.Zero)
            : DateTimeOffset.UtcNow;
        return new DevErrorEntry(time, program, message, occurrences);
    }

    /// <summary>Reads the entries since the last Clear and follows the log for new ones.</summary>
    private void Follow()
    {
        DateTimeOffset cleared = ClearedAt();
        string since =
            cleared == DateTimeOffset.MinValue
                ? ProviderQuery
                : string.Create(
                    CultureInfo.InvariantCulture,
                    $"*[System[Provider[@Name='RefineID'] and TimeCreated[@SystemTime>'{cleared.UtcDateTime.ToString(QueryTimeFormat, CultureInfo.InvariantCulture)}']]]"
                );
        List<DevErrorEntry> stored = [];
        try
        {
            using EventLogReader reader = new(
                new EventLogQuery(LogName, PathType.LogName, since) { ReverseDirection = true }
            );
            while (stored.Count < Capacity && reader.ReadEvent() is EventRecord record)
            {
                using (record)
                {
                    if (EntryOf(record) is DevErrorEntry entry)
                    {
                        stored.Add(entry);
                    }
                }
            }
        }
        catch (EventLogException error)
        {
            DevErrorLog.Report("Log window could not read the event log", error);
        }

        stored.Reverse();
        foreach (DevErrorEntry entry in stored)
        {
            this.Add(entry);
        }

        this.Render();
        if (this.entries.Count > 0)
        {
            this.Present();
        }

        try
        {
            watcher = new EventLogWatcher(
                new EventLogQuery(LogName, PathType.LogName, ProviderQuery)
            );
            watcher.EventRecordWritten += this.OnEventRecordWritten;
            watcher.Enabled = true;
        }
        catch (EventLogException error)
        {
            DevErrorLog.Report("Log window could not follow the event log", error);
        }
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs args)
    {
        using EventRecord? record = args.EventRecord;
        if (record is null || EntryOf(record) is not DevErrorEntry entry)
        {
            return;
        }

        _ = this.dispatcher.TryEnqueue(() =>
        {
            this.Add(entry);
            this.Render();
            this.Present();
        });
    }

    /// <summary>Adds <paramref name="entry"/> as the newest, folding a repeat of the newest into it.</summary>
    private void Add(DevErrorEntry entry)
    {
        if (this.entries.Count > 0 && this.entries[0].Repeats(entry))
        {
            this.entries[0] = entry with
            {
                Occurrences = this.entries[0].Occurrences + entry.Occurrences,
            };
            return;
        }

        this.entries.Insert(0, entry);
        if (this.entries.Count > Capacity)
        {
            this.entries.RemoveAt(this.entries.Count - 1);
        }
    }

    /// <summary>Shows every entry, newest first, as selectable text.</summary>
    private void Render()
    {
        Brush secondary = (Brush)Application.Current.Resources["TextFillColorSecondaryBrush"];
        Brush critical = (Brush)Application.Current.Resources["SystemFillColorCriticalBrush"];
        this.rows.Children.Clear();
        foreach (DevErrorEntry entry in this.entries)
        {
            TextBlock row = new()
            {
                IsTextSelectionEnabled = true,
                TextWrapping = TextWrapping.Wrap,
            };
            row.Inlines.Add(
                new Run
                {
                    Text = string.Create(
                        CultureInfo.InvariantCulture,
                        $"{entry.Time.ToLocalTime():HH:mm:ss}  "
                    ),
                    Foreground = secondary,
                }
            );
            row.Inlines.Add(new Run { Text = entry.Text, Foreground = critical });
            this.rows.Children.Add(row);
        }
    }

    /// <summary>Brings the window up beside the main window without taking the keyboard.</summary>
    private void Present()
    {
        this.Place();
        this.AppWindow.Show(false);
    }

    /// <summary>Puts every entry on the clipboard, one per line and oldest first, as a log reads.</summary>
    private void CopyAll()
    {
        StringBuilder text = new();
        for (int index = this.entries.Count - 1; index >= 0; index--)
        {
            DevErrorEntry entry = this.entries[index];
            _ = text.Append(
                    CultureInfo.InvariantCulture,
                    $"{entry.Time.ToString("O", CultureInfo.InvariantCulture)} {entry.Program} {entry.Text}"
                )
                .Append('\n');
        }

        DataPackage package = new();
        package.SetText(text.ToString());
        Clipboard.SetContent(package);
    }

    /// <summary>Hides every entry up to now, for this and later launches.</summary>
    private void Clear()
    {
        KeepClearedAt(DateTimeOffset.UtcNow);
        this.entries.Clear();
        this.Render();
    }

    /// <summary>Closing hides the window, so it keeps its entries and place.</summary>
    private void OnClosing(AppWindow sender, AppWindowClosingEventArgs args)
    {
        if (this.shuttingDown)
        {
            return;
        }

        args.Cancel = true;
        sender.Hide();
    }
}
#endif
