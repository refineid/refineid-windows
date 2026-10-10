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

using System.Diagnostics;
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
    /// <summary>Requester label the phone shows during pairing.</summary>
    private const string RequesterName = "RefineID Windows";

    /// <summary>Pairing-state poll cadence.</summary>
    private static readonly TimeSpan PollInterval = TimeSpan.FromMilliseconds(700);

    private readonly DispatcherQueue dispatcher;
    private readonly DispatcherTimer cardPollTimer;
    private string? remoteHolder;
    private string? selectedReader;

    public MainPage()
    {
        this.InitializeComponent();
        this.dispatcher = DispatcherQueue.GetForCurrentThread();
        this.cardPollTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        this.cardPollTimer.Tick += (s, e) => this.CheckLocalCard();
        this.DiagnosticsText.Text = DiagnosticsLabel();
        this.Loaded += this.OnLoaded;
    }

#if DEBUG
    /// <summary>Debug-only launch flag that opens pairing on launch.</summary>
    private const string AutoPairArgument = "--pair";
#endif

    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        this.Loaded -= this.OnLoaded;
        // Once per run: disable the inbound rule earlier releases opened for
        // the phone, when that needs no administrator rights.
        _ = Task.Run(FirewallService.DisableLegacyRule);
        this.CheckLocalCard();
        this.cardPollTimer.Start();
        this.ShowDriverLaneHintIfNeeded();
#if DEBUG
        if (
            Array.Exists(Environment.GetCommandLineArgs(), argument => argument == AutoPairArgument)
        )
        {
            await this.RunRemoteCardAsync().ConfigureAwait(true);
        }
#endif
    }

    private static string DiagnosticsLabel()
    {
        Version? version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
        return version is null
            ? "RefineID"
            : $"RefineID {version.Major}.{version.Minor}.{version.Build}.{version.Revision}";
    }

    private async void ConnectRemoteReader_Click(object sender, RoutedEventArgs args) =>
        await this.RunRemoteCardAsync().ConfigureAwait(true);

    private async Task RunRemoteCardAsync()
    {
        var dialog = new PairingDialog(RequesterName, this.dispatcher, PollInterval)
        {
            XamlRoot = this.XamlRoot,
        };
        _ = await dialog.ShowAsync();

        if (dialog.PairedHandle is ulong pairedHandle)
        {
            await this.ReadPairedCardAsync(pairedHandle).ConfigureAwait(true);
        }
        else if (dialog.Failure is string failure)
        {
            this.ShowError(failure);
        }
    }

    private async Task ReadPairedCardAsync(ulong handle)
    {
        this.SetBusy(true);
        try
        {
            CardReading reading = await Task.Run(() => NativeRappService.ReadCard(handle))
                .ConfigureAwait(true);
            string holder = string.IsNullOrWhiteSpace(reading.Identity.PersonId)
                ? reading.Identity.DisplayName
                : $"{reading.Identity.DisplayName} {reading.Identity.PersonId}";
            this.remoteHolder = holder;
            this.HolderText.Text = holder;
            this.HolderText.Visibility = Visibility.Visible;
            this.ForgetIdentityButton.Visibility = Visibility.Visible;
            this.ConnectRemoteReaderButton.Visibility = Visibility.Collapsed;
            this.ShowSuccess($"Read the remote card of {holder}.");
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
        }
        finally
        {
            this.SetBusy(false);
            NativeRappService.EndPairing(handle);
        }
    }

    private async void ForgetIdentity_Click(object sender, RoutedEventArgs args) =>
        await this.ConfirmForgetIdentityAsync().ConfigureAwait(true);

    private async Task ConfirmForgetIdentityAsync()
    {
        // The scan was the consent to read; forgetting is destructive to the
        // device-local identity, so it takes its own explicit confirmation.
        // Cancel is the safe default the way Windows dialogs expect.
        var dialog = new ContentDialog
        {
            XamlRoot = this.XamlRoot,
            Title = "Forget identity?",
            Content = string.IsNullOrWhiteSpace(this.HolderText.Text)
                ? "The remote card will be removed from this device."
                : $"The remote card of {this.HolderText.Text} will be removed from this device.",
            PrimaryButtonText = "Forget",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Close,
        };

        if (await dialog.ShowAsync() == ContentDialogResult.Primary)
        {
            this.ForgetIdentity();
        }
    }

    private void ForgetIdentity()
    {
        this.remoteHolder = null;
        this.HolderText.Text = string.Empty;
        this.HolderText.Visibility = Visibility.Collapsed;
        this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
        this.ConnectRemoteReaderButton.Visibility = Visibility.Visible;

        // Clearing the row is not enough now that a pairing is durable: drop
        // the stored pair keys from the device-only credential too.
        try
        {
            NativeRappService.ForgetPairings();
            this.StatusInfoBar.IsOpen = false;
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
        }

        this.CheckLocalCard();
    }

    private async void ShowDriverLaneHintIfNeeded()
    {
        LocalCardSupport support = await Task.Run(LocalCardService.DetectLocalCardSupport)
            .ConfigureAwait(true);

        if (support.State == "driver_not_installed")
        {
            this.ShowStatus(
                InfoBarSeverity.Informational,
                "Local-card functions need the FINEID drivers. Phone-powered signing via Remote Reader still works."
            );
        }
    }

    private async void CheckLocalCard()
    {
        try
        {
            IReadOnlyList<string> readers = await Task.Run(LocalCardService.PresentReaders)
                .ConfigureAwait(true);

            // Prefer the last selected reader if still present.
            string? targetReader = null;
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
                LocalCardSnapshot? snapshot = await Task.Run(() =>
                        LocalCardService.Inspect(targetReader)
                    )
                    .ConfigureAwait(true);
                if (snapshot is not null)
                {
                    this.selectedReader = targetReader;
                    this.UpdateLocalCardUi(snapshot);
                    return;
                }
            }

            this.UpdateLocalCardDisconnected();
        }
        catch (NativeRappException ex)
        {
            Debug.WriteLine($"CheckLocalCardAsync native error: {ex.Message}");
            this.UpdateLocalCardDisconnected();
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"CheckLocalCardAsync JSON parse error: {ex.Message}");
            this.UpdateLocalCardDisconnected();
        }
    }

    private void UpdateLocalCardUi(LocalCardSnapshot snapshot)
    {
        this.SignCard.IsEnabled = true;

        if (!string.IsNullOrWhiteSpace(snapshot.Person))
        {
            this.HolderText.Text = snapshot.Person;
            this.HolderText.Visibility = Visibility.Visible;
            this.ConnectRemoteReaderButton.Visibility = Visibility.Collapsed;
            this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
        }
        else if (this.remoteHolder is null)
        {
            this.HolderText.Text = string.Empty;
            this.HolderText.Visibility = Visibility.Collapsed;
            this.ConnectRemoteReaderButton.Visibility = Visibility.Visible;
            this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
        }
    }

    private void UpdateLocalCardDisconnected()
    {
        if (this.remoteHolder is null)
        {
            this.HolderText.Text = string.Empty;
            this.HolderText.Visibility = Visibility.Collapsed;
            this.ConnectRemoteReaderButton.Visibility = Visibility.Visible;
            this.ForgetIdentityButton.Visibility = Visibility.Collapsed;
            this.SignCard.IsEnabled = false;
        }
        else
        {
            this.HolderText.Text = this.remoteHolder;
            this.HolderText.Visibility = Visibility.Visible;
            this.ConnectRemoteReaderButton.Visibility = Visibility.Collapsed;
            this.ForgetIdentityButton.Visibility = Visibility.Visible;
            this.SignCard.IsEnabled = true;
        }
    }

    private void SetBusy(bool busy)
    {
        this.BusyOverlay.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        this.BusyOverlay.IsHitTestVisible = busy;
    }

    private void ShowSuccess(string message) => this.ShowStatus(InfoBarSeverity.Success, message);

    private void ShowError(string message) => this.ShowStatus(InfoBarSeverity.Error, message);

    private void ShowStatus(InfoBarSeverity severity, string message)
    {
        this.StatusInfoBar.Severity = severity;
        this.StatusInfoBar.Message = message;
        this.StatusInfoBar.IsOpen = true;
    }
}
