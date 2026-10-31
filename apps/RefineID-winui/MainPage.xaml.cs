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

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.Json;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

/// <summary>
/// The requester main screen: Document, Card, and Identity, mirroring the
/// mobile app. Remote Card and Connect Remote Reader drive the RAPP pairing
/// ceremony and a public card read; no credential is ever handled here.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by the root Frame through XAML type activation."
)]
internal sealed partial class MainPage : Page
{
    /// <summary>
    /// The name the phone shows for this requester: the computer's name,
    /// as a Mac and an iPhone send theirs. The phone names the platform
    /// itself, so the name does not repeat it.
    /// </summary>
    private static readonly string RequesterName = Environment.MachineName;

    /// <summary>Pairing-state poll cadence.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(700);

    private readonly DispatcherQueue dispatcher;
    private readonly DispatcherTimer cardPollTimer;
    private string? remoteHolder;

    /// <summary>Whether the card in a local reader can sign.</summary>
    private bool localCardSigns;

    /// <summary>
    /// The reader whose card sits on the contactless antenna without a
    /// stored access number, so the identity row leads to the entry that
    /// proves and stores it; null otherwise.
    /// </summary>
    private string? contactlessReaderWithoutCan;

    /// <summary>Whether the device holds a pairing, read or not.</summary>
    private bool hasPairing;
    private string? selectedReader;
    private bool started;

    /// <summary>The readers holding a card at the last inspection.</summary>
    private IReadOnlyList<string>? inspectedReaders;
    private bool checkingLocalCard;

    /// <summary>
    /// The serial of the last unactivated card seen, so the PIN page opens
    /// once per card and a return to this page does not open it again.
    /// Forgotten when no reader holds a card or the card cannot be read.
    /// </summary>
    private string? unactivatedSerial;

    /// <summary>Whether the pairing dialog is open over this page.</summary>
    private bool pairing;

    public MainPage()
    {
        this.InitializeComponent();
        this.dispatcher = DispatcherQueue.GetForCurrentThread();
        this.cardPollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        this.cardPollTimer.Tick += (s, e) => this.CheckLocalCard();
        // Wired here on purpose: a Click attribute on the toolkit's
        // SettingsCard in the page markup makes the page fail to load.
        this.PersonCard.Click += this.ConnectRemoteReader_Click;
        this.DiagnosticsText.Text = DiagnosticsLabel();
#if DEBUG
        this.DiagnosticsText.Tapped += (sender, args) => DevErrorWindow.ShowWindow();
#endif
        this.Loaded += this.OnLoaded;
        this.Unloaded += this.OnUnloaded;
    }

#if DEBUG
    /// <summary>Debug-only launch flag that opens pairing on launch.</summary>
    private const string AutoPairArgument = "--pair";
#endif

    /// <summary>
    /// Runs on every return to this page (it is cached across navigation to
    /// the settings page); the once-per-run work is guarded.
    /// </summary>
    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        // The PIN page may have changed the card, so the card is inspected
        // again on every arrival, not only when the reader list changes.
        this.inspectedReaders = null;
        if (this.started)
        {
            this.cardPollTimer.Start();
            await this.CheckLocalCardAsync().ConfigureAwait(true);
            return;
        }

        this.started = true;
        // The first check decides which page opens; this one stays hidden
        // until it has, and stays hidden when the card led elsewhere.
        await this.CheckLocalCardAsync().ConfigureAwait(true);
        if (ReferenceEquals(this.Frame.Content, this))
        {
            this.ContentRoot.Visibility = Visibility.Visible;
        }

        this.cardPollTimer.Start();
        // Once per run: disable the inbound rule earlier releases opened for
        // the phone, when that needs no administrator rights.
        _ = Task.Run(FirewallService.DisableLegacyRule);
        this.ShowDriverLaneHintIfNeeded();
        bool quiet = true;
#if DEBUG
        quiet = !Array.Exists(
            Environment.GetCommandLineArgs(),
            argument => argument == AutoPairArgument
        );
#endif
        await this.RunRemoteCardAsync(quiet).ConfigureAwait(true);
    }

    /// <summary>The settings page polls the readers itself while it is shown.</summary>
    private void OnUnloaded(object sender, RoutedEventArgs args) => this.cardPollTimer.Stop();

    /// <summary>A return to this page shows it at once; only the first arrival waits.</summary>
    protected override void OnNavigatedTo(Microsoft.UI.Xaml.Navigation.NavigationEventArgs args)
    {
        base.OnNavigatedTo(args);
        if (this.started)
        {
            this.ContentRoot.Visibility = Visibility.Visible;
        }
    }

    private void Pins_Click(object sender, RoutedEventArgs args) =>
        this.Frame.Navigate(typeof(CardPage));

    private void Verify_Click(object sender, RoutedEventArgs args) =>
        this.Frame.Navigate(typeof(DocumentPage), DocumentMode.Verify);

    private void Sign_Click(object sender, RoutedEventArgs args) =>
        this.Frame.Navigate(typeof(DocumentPage), DocumentMode.Sign);

    private static string DiagnosticsLabel()
    {
        Version? version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        return version is null
            ? "RefineID"
            : $"RefineID {version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
    }

    /// <summary>
    /// The button stays only while no read through the stored pairing has
    /// succeeded, so pressing it pairs afresh: a new pairing replaces the
    /// stored one, which is the only way out when the phone forgot it.
    /// </summary>
    private async void ConnectRemoteReader_Click(object sender, RoutedEventArgs args)
    {
        if (this.contactlessReaderWithoutCan is string reader)
        {
            // The PIN page's contactless entry proves the access number and
            // stores it; the card reads on the return here.
            this.Frame.Navigate(typeof(CardPage), reader);
            return;
        }

        await this.PairAndReadAsync().ConfigureAwait(true);
    }

    /// <summary>
    /// Reads the card through the pairing this device already holds. On
    /// launch the read is quiet: a phone that is not around is not an error
    /// worth a notice.
    /// </summary>
    private async Task RunRemoteCardAsync(bool quiet)
    {
        ulong handle;
        try
        {
            handle = (
                await Task.Run(() => NativeRappService.OpenPairing(RequesterName))
                    .ConfigureAwait(true)
            ).Handle;
        }
        catch (NativeRappException error) when (error.Code == "no_pairing")
        {
            if (!quiet)
            {
                await this.PairAndReadAsync().ConfigureAwait(true);
            }

            return;
        }
        catch (NativeRappException error)
        {
            if (!quiet)
            {
                this.ShowError(error.Message);
            }

            return;
        }

        // The pairing exists, so forgetting it is an action even before a
        // read has succeeded.
        this.hasPairing = true;
        this.ForgetIdentityButton.Visibility = Visibility.Visible;
        await this.ReadPairedCardAsync(handle, quiet).ConfigureAwait(true);
    }

    private async Task PairAndReadAsync()
    {
        var dialog = new PairingDialog(RequesterName, this.dispatcher, PollInterval)
        {
            XamlRoot = this.XamlRoot,
        };
        this.pairing = true;
        try
        {
            _ = await dialog.ShowAsync();
        }
        finally
        {
            this.pairing = false;
        }

        if (dialog.PairedHandle is ulong pairedHandle)
        {
            this.hasPairing = true;
            this.ForgetIdentityButton.Visibility = Visibility.Visible;
            await this.ReadPairedCardAsync(pairedHandle, quiet: false).ConfigureAwait(true);
        }
    }

    private async Task ReadPairedCardAsync(ulong handle, bool quiet)
    {
        // A quiet read runs behind the screen; only a requested read blocks it.
        if (!quiet)
        {
            this.SetBusy(true);
        }

        try
        {
            CardReading reading = await Task.Run(() => NativeRappService.ReadCard(handle))
                .ConfigureAwait(true);

            string holder = reading.Identity.DisplayName;
            this.remoteHolder = holder;
            this.ShowHolder(holder);
            // The phone's card signs, whatever the local reader holds.
            this.RefreshSignEntry();
            this.StatusInfoBar.IsOpen = false;
        }
        catch (NativeRappException error)
        {
            if (!quiet)
            {
                this.ShowError(error.Message);
            }
        }
        finally
        {
            this.SetBusy(false);
            NativeRappService.EndPairing(handle);
        }
    }

    /// <summary>
    /// The click forgets at once. The button is disabled while the forget
    /// runs: the busy overlay stops a second click, and this stops a
    /// repeated key press from starting a second forget.
    /// </summary>
    private async void ForgetIdentity_Click(object sender, RoutedEventArgs args)
    {
        this.ForgetIdentityButton.IsEnabled = false;
        try
        {
            await this.ForgetIdentityAsync().ConfigureAwait(true);
        }
        finally
        {
            this.ForgetIdentityButton.IsEnabled = true;
        }
    }

    /// <summary>
    /// Drops the stored pair keys from the device-only credential. The
    /// native call first tells the phone over a short network session, so it
    /// runs off the UI thread behind the busy overlay.
    /// </summary>
    private async Task ForgetIdentityAsync()
    {
        this.SetBusy(true);
        try
        {
            await Task.Run(NativeRappService.ForgetPairings).ConfigureAwait(true);
            this.StatusInfoBar.IsOpen = false;
            this.remoteHolder = null;
            this.hasPairing = false;
            this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
            this.ShowNoHolder();
            this.RefreshSignEntry();
            // The focused button is gone; keyboard focus moves to the row.
            _ = this.PersonCard.Focus(FocusState.Programmatic);
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
            return;
        }
        finally
        {
            this.SetBusy(false);
        }

        await this.CheckLocalCardAsync().ConfigureAwait(true);
    }

    private async void ShowDriverLaneHintIfNeeded()
    {
        LocalCardSupport support = await Task.Run(LocalCardService.DetectLocalCardSupport)
            .ConfigureAwait(true);

        if (support.State == "driver_not_installed")
        {
            this.ShowStatus(InfoBarSeverity.Informational, Strings.Get("DriverLaneHint"));
        }
    }

    /// <summary>
    /// A tick lists the readers holding a card, which touches no card; the
    /// card is inspected only when that list changes, so an idle window
    /// leaves the reader alone.
    /// </summary>
    private async void CheckLocalCard() => await this.CheckLocalCardAsync().ConfigureAwait(true);

    private async Task CheckLocalCardAsync()
    {
        if (this.checkingLocalCard)
        {
            return;
        }

        this.checkingLocalCard = true;
        try
        {
            await this.InspectLocalCardOnChangeAsync().ConfigureAwait(true);
        }
        finally
        {
            this.checkingLocalCard = false;
        }
    }

    private async Task InspectLocalCardOnChangeAsync()
    {
        IReadOnlyList<string> readers;
        try
        {
            readers = await Task.Run(LocalCardService.PresentReaders).ConfigureAwait(true);
        }
        catch (NativeRappException)
        {
            this.inspectedReaders = null;
            this.unactivatedSerial = null;
            this.PinsCard.Visibility = Visibility.Collapsed;
            this.UpdateLocalCardDisconnected();
            return;
        }

        if (
            this.inspectedReaders is not null
            && readers.SequenceEqual(this.inspectedReaders, StringComparer.Ordinal)
        )
        {
            return;
        }

        // The PIN page works on a reader attached to this computer, with or
        // without a card in it, so the entry follows the reader list alone.
        this.PinsCard.Visibility = readers.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (readers.Count == 0)
        {
            this.unactivatedSerial = null;
        }

        // Recorded once the inspection is done, so a failed one is tried
        // again on the next tick.
        this.inspectedReaders = null;

        string? targetReader = null;
        try
        {
            // Prefer the last selected reader if still present.
            if (this.selectedReader is not null)
            {
                targetReader = readers.FirstOrDefault(r =>
                    string.Equals(r, this.selectedReader, StringComparison.Ordinal)
                );
                if (targetReader is null)
                {
                    this.selectedReader = null;
                }
            }

            if (targetReader is null && readers.Count > 0)
            {
                targetReader =
                    readers.FirstOrDefault(reader =>
                        !reader.Contains("Virtual", StringComparison.OrdinalIgnoreCase)
                    ) ?? readers[0];
            }

            if (targetReader is not null)
            {
                LocalCardSnapshot snapshot = await Task.Run(() =>
                        LocalCardService.Inspect(targetReader)
                    )
                    .ConfigureAwait(true);
                this.selectedReader = targetReader;
                this.UpdateLocalCardUi(snapshot);
                this.inspectedReaders = readers;
                return;
            }

            this.UpdateLocalCardDisconnected();
            this.inspectedReaders = readers;
        }
        catch (NativeRappException error)
            when (error.Code == "access_number_required" && targetReader is not null)
        {
            // A card on the contactless antenna, not yet primed on this
            // computer: the row leads to the entry that primes it, and the
            // reader list is recorded so the card is not asked again until
            // something changes or the PIN page returns.
            this.unactivatedSerial = null;
            this.ShowAccessNumberNeeded(targetReader);
            this.inspectedReaders = readers;
        }
        catch (NativeRappException)
        {
            this.unactivatedSerial = null;
            this.UpdateLocalCardDisconnected();
        }
        catch (JsonException)
        {
            this.unactivatedSerial = null;
            this.UpdateLocalCardDisconnected();
        }
    }

    private void UpdateLocalCardUi(LocalCardSnapshot snapshot)
    {
        // A card that still waits for its activation cannot sign or
        // authenticate, so the activation flow opens on the PIN page the
        // first time the card is seen, while this page is the one shown and
        // no pairing dialog is open over it. A card first seen from another
        // page is remembered too, so a return here does not send the holder
        // back to the page they just left.
        // A card that waits for its activation cannot sign.
        this.localCardSigns = !snapshot.LooksUnactivated;
        this.RefreshSignEntry();
        if (snapshot.LooksUnactivated)
        {
            bool firstSight = !string.Equals(
                snapshot.Serial,
                this.unactivatedSerial,
                StringComparison.Ordinal
            );
            this.unactivatedSerial = snapshot.Serial;
            if (firstSight && !this.pairing && ReferenceEquals(this.Frame.Content, this))
            {
                this.Frame.Navigate(typeof(CardPage), snapshot.Reader);
            }
        }

        if (!string.IsNullOrWhiteSpace(snapshot.Person))
        {
            this.ShowHolder(snapshot.Person);
            this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
        }
        else if (this.remoteHolder is null)
        {
            this.ShowNoHolder();
            this.ForgetIdentityButton.Visibility = this.ForgetVisibility();
        }
    }

    private void UpdateLocalCardDisconnected()
    {
        this.localCardSigns = false;
        if (this.remoteHolder is null)
        {
            this.ShowNoHolder();
            this.ForgetIdentityButton.Visibility = this.ForgetVisibility();
        }
        else
        {
            this.ShowHolder(this.remoteHolder);
            this.ForgetIdentityButton.Visibility = Visibility.Visible;
        }

        this.RefreshSignEntry();
    }

    /// <summary>The identity row is headed by its holder, as on the other platforms.</summary>
    private void ShowHolder(string holder)
    {
        this.contactlessReaderWithoutCan = null;
        this.PersonCard.Header = holder;
        this.PersonCard.IsClickEnabled = false;
    }

    /// <summary>
    /// A card on the contactless antenna without a stored access number:
    /// the row is the way to prime it, and nothing signs until it is.
    /// </summary>
    private void ShowAccessNumberNeeded(string reader)
    {
        this.contactlessReaderWithoutCan = reader;
        this.localCardSigns = false;
        this.PersonCard.Header = Strings.Get("ContactlessAccessNumber");
        this.PersonCard.IsClickEnabled = true;
        this.ForgetIdentityButton.Visibility = this.ForgetVisibility();
        this.RefreshSignEntry();
    }

    /// <summary>
    /// Without a holder the row is the way to get one: it connects the
    /// remote reader.
    /// </summary>
    private void ShowNoHolder()
    {
        this.contactlessReaderWithoutCan = null;
        this.PersonCard.Header = Strings.Get("ConnectRemoteReader");
        this.PersonCard.IsClickEnabled = true;
    }

    /// <summary>
    /// Sign is offered while a card can sign: the card in a local reader
    /// once activated, or the phone's card through the pairing. The entry
    /// is absent rather than grey otherwise.
    /// </summary>
    private void RefreshSignEntry() =>
        this.SignCard.Visibility =
            this.localCardSigns || this.remoteHolder is not null
                ? Visibility.Visible
                : Visibility.Collapsed;

    /// <summary>The forget button stays while a pairing exists, read or not.</summary>
    private Visibility ForgetVisibility() =>
        this.hasPairing ? Visibility.Visible : Visibility.Collapsed;

    private void SetBusy(bool busy)
    {
        this.BusyOverlay.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        this.BusyOverlay.IsHitTestVisible = busy;
    }

    private void ShowError(string message) => this.ShowStatus(InfoBarSeverity.Error, message);

    private void ShowStatus(InfoBarSeverity severity, string message)
    {
        this.StatusInfoBar.Severity = severity;
        this.StatusInfoBar.Message = message;
        this.StatusInfoBar.IsOpen = true;
    }
}
