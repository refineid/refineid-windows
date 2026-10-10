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
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

/// <summary>
/// The card settings screen: the card in the selected reader, its PIN and
/// recovery status, PIN change and reset, activation, and the contactless
/// CAN. Every modifying command is bound to the inspected reader and card
/// serial; PINs are read from the boxes, cleared at once, and only ever
/// handed to the native card service.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated by the root Frame through XAML type activation."
)]
internal sealed partial class CardPage : Page
{
    /// <summary>
    /// Card-present readers are listed on this cadence so inserted, removed,
    /// and tapped cards appear without user action.
    /// </summary>
    private static readonly TimeSpan ReaderPollInterval = TimeSpan.FromSeconds(2);

    private readonly DispatcherTimer readerPollTimer;
    private LocalCardSnapshot? snapshot;
    private bool busy;
    private bool refreshingReaders;
    private bool polling;

    public CardPage()
    {
        this.InitializeComponent();
        this.readerPollTimer = new DispatcherTimer { Interval = ReaderPollInterval };
        this.readerPollTimer.Tick += (s, e) => this.PollReaders();
        this.Loaded += this.OnLoaded;
        this.Unloaded += this.OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        await this.RefreshReadersAsync().ConfigureAwait(true);
        this.readerPollTimer.Start();
    }

    private void OnUnloaded(object sender, RoutedEventArgs args) => this.readerPollTimer.Stop();

    /// <summary>
    /// A tick lists readers only; the card is inspected again only when the
    /// set of card-present readers changes.
    /// </summary>
    private async void PollReaders()
    {
        if (this.busy || this.polling)
        {
            return;
        }

        this.polling = true;
        try
        {
            IReadOnlyList<string> readers = await Task.Run(LocalCardService.PresentReaders)
                .ConfigureAwait(true);
            IReadOnlyList<string> shown =
                this.ReaderComboBox.ItemsSource as IReadOnlyList<string> ?? [];
            if (!this.busy && !readers.SequenceEqual(shown, StringComparer.Ordinal))
            {
                await this.RefreshReadersAsync().ConfigureAwait(true);
            }
        }
        finally
        {
            this.polling = false;
        }
    }

    private async void ReaderComboBox_SelectionChanged(
        object sender,
        SelectionChangedEventArgs args
    )
    {
        if (this.refreshingReaders || this.busy)
        {
            return;
        }

        if (this.SelectedReader() is null)
        {
            this.ClearCard();
            return;
        }

        await this.RunCardOperationAsync(this.InspectSelectedReaderAsync).ConfigureAwait(true);
    }

    private async void EnableNfcButton_Click(object sender, RoutedEventArgs args)
    {
        string? reader = this.SelectedReader();
        if (reader is null)
        {
            this.ShowError("Select a reader with a card first.");
            return;
        }

        string can = this.CanBox.Password;
        this.CanBox.Password = string.Empty;
        await this.RunCardOperationAsync(async () =>
            {
                ContactlessSnapshot result = await Task.Run(() =>
                        LocalCardService.PrimeContactless(reader, can)
                    )
                    .ConfigureAwait(true);
                this.NfcResultText.Text =
                    $"{DisplayPerson(result.Person)}, serial {result.Serial}. "
                    + $"PIN1: {FormatStatus(result.Pin1)}. PIN2: {FormatStatus(result.Pin2)}.";
                this.NfcResultPanel.Visibility = Visibility.Visible;
                this.ShowSuccess("NFC access enabled. The CAN is saved on this device.");
            })
            .ConfigureAwait(true);
    }

    private async void ChangePinButton_Click(object sender, RoutedEventArgs args)
    {
        if (!this.TryGetBoundCard(out string reader, out string serial))
        {
            return;
        }

        PinSlot slot = SlotFrom(this.ChangeSlotBox);
        string current = this.CurrentPinBox.Password;
        string next = this.NewPinBox.Password;
        string confirmation = this.NewPinConfirmationBox.Password;
        Clear(this.CurrentPinBox, this.NewPinBox, this.NewPinConfirmationBox);

        await this.RunMutationAsync(() =>
                LocalCardService.ChangePin(reader, serial, slot, current, next, confirmation)
            )
            .ConfigureAwait(true);
    }

    private async void UnblockPinButton_Click(object sender, RoutedEventArgs args)
    {
        if (!this.TryGetBoundCard(out string reader, out string serial))
        {
            return;
        }

        PinSlot slot = SlotFrom(this.UnblockSlotBox);
        string puk = this.PukBox.Password;
        string next = this.UnblockNewPinBox.Password;
        string confirmation = this.UnblockConfirmationBox.Password;
        Clear(this.PukBox, this.UnblockNewPinBox, this.UnblockConfirmationBox);

        await this.RunMutationAsync(() =>
                LocalCardService.UnblockPin(reader, serial, slot, puk, next, confirmation)
            )
            .ConfigureAwait(true);
    }

    private async void ActivateButton_Click(object sender, RoutedEventArgs args)
    {
        if (!this.TryGetBoundCard(out string reader, out string serial))
        {
            return;
        }

        string activationCode = this.ActivationCodeBox.Password;
        string pin1 = this.ActivationPin1Box.Password;
        string pin1Confirmation = this.ActivationPin1ConfirmationBox.Password;
        string pin2 = this.ActivationPin2Box.Password;
        string pin2Confirmation = this.ActivationPin2ConfirmationBox.Password;
        Clear(
            this.ActivationCodeBox,
            this.ActivationPin1Box,
            this.ActivationPin1ConfirmationBox,
            this.ActivationPin2Box,
            this.ActivationPin2ConfirmationBox
        );

        await this.RunMutationAsync(() =>
                LocalCardService.Activate(
                    reader,
                    serial,
                    activationCode,
                    pin1,
                    pin1Confirmation,
                    pin2,
                    pin2Confirmation,
                    allowReactivate: false
                )
            )
            .ConfigureAwait(true);
    }

    private async Task RefreshReadersAsync()
    {
        if (this.busy)
        {
            return;
        }

        string? previous = this.SelectedReader();
        await this.RunCardOperationAsync(async () =>
            {
                IReadOnlyList<string> readers = await Task.Run(LocalCardService.PresentReaders)
                    .ConfigureAwait(true);
                this.refreshingReaders = true;
                try
                {
                    this.ReaderComboBox.ItemsSource = readers;
                    this.ReaderComboBox.SelectedItem =
                        previous is not null && readers.Contains(previous, StringComparer.Ordinal)
                            ? previous
                            : readers.Count > 0
                                ? readers[0]
                                : null;
                }
                finally
                {
                    this.refreshingReaders = false;
                }

                if (readers.Count == 0)
                {
                    this.ClearCard();
                    this.StatusInfoBar.IsOpen = false;
                    return;
                }

                await this.InspectSelectedReaderAsync().ConfigureAwait(true);
            })
            .ConfigureAwait(true);
    }

    private async Task InspectSelectedReaderAsync()
    {
        string? reader = this.SelectedReader();
        if (reader is null)
        {
            this.ClearCard();
            return;
        }

        LocalCardSnapshot inspected = await Task.Run(() => LocalCardService.Inspect(reader))
            .ConfigureAwait(true);
        this.snapshot = inspected;
        this.PersonText.Text = DisplayPerson(inspected.Person);
        this.ModelText.Text = inspected.Model;
        this.SerialText.Text = inspected.Serial;
        this.Pin1StatusText.Text = FormatStatus(inspected.Pin1, inspected.Pin1Changed);
        this.Pin2StatusText.Text = FormatStatus(inspected.Pin2, inspected.Pin2Changed);
        this.PukStatusText.Text = FormatStatus(inspected.Puk);
        this.GenerationText.Text = inspected.Generation switch
        {
            "newer" => "Current single-use activation scheme",
            "older" => "Legacy reusable activation scheme",
            _ => "Unknown",
        };
        this.ActivationHintText.Text = inspected.ActivationCodeLength is int length
            ? $"{length}-digit activation code."
            : "Unknown activation code. Activation refused.";
        this.CardPanel.Visibility = Visibility.Visible;
        this.ManagementPanel.IsHitTestVisible = true;
        this.ManagementPanel.Opacity = 1;
        this.StatusInfoBar.IsOpen = false;
    }

    private async Task RunMutationAsync(Func<MutationResult> operation)
    {
        await this.RunCardOperationAsync(async () =>
            {
                MutationResult result = await Task.Run(operation).ConfigureAwait(true);
                await this.InspectSelectedReaderAsync().ConfigureAwait(true);
                if (result.Succeeded)
                {
                    this.ShowSuccess(result.Message);
                }
                else
                {
                    this.ShowStatus(InfoBarSeverity.Warning, result.Message);
                }
            })
            .ConfigureAwait(true);
    }

    private async Task RunCardOperationAsync(Func<Task> operation)
    {
        if (this.busy)
        {
            return;
        }

        this.SetBusy(true);
        try
        {
            await operation().ConfigureAwait(true);
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
        }
        catch (JsonException)
        {
            this.ShowError("The card service response could not be read.");
        }
        finally
        {
            this.SetBusy(false);
        }
    }

    private bool TryGetBoundCard(out string reader, out string serial)
    {
        reader = this.SelectedReader() ?? string.Empty;
        serial = this.snapshot?.Serial ?? string.Empty;
        if (reader.Length > 0 && serial.Length > 0)
        {
            return true;
        }

        this.ShowError("Insert the card in a contact reader first.");
        return false;
    }

    private string? SelectedReader() => this.ReaderComboBox.SelectedItem as string;

    private static PinSlot SlotFrom(ComboBox box) =>
        box.SelectedIndex == 1 ? PinSlot.Pin2 : PinSlot.Pin1;

    private static string DisplayPerson(string person) =>
        string.IsNullOrWhiteSpace(person) ? "Not available" : person;

    private static string FormatStatus(CredentialStatus? status, bool? changed = null)
    {
        if (status is null)
        {
            return "Not available";
        }

        string value = status.State switch
        {
            "verified" => "Verified in this card session",
            "ready" when status.AttemptsRemaining is byte attempts =>
                $"Ready, {attempts} attempts remaining",
            "locked" => "Blocked",
            "invalidated" => "Recovery unavailable",
            "no_information" => "No counter information",
            "other" when status.StatusWord is ushort statusWord => $"Card status 0x{statusWord:X4}",
            _ => status.State,
        };

        return changed switch
        {
            true => $"{value}; changed from factory value",
            false => $"{value}; still at factory value",
            null => value,
        };
    }

    private static void Clear(params PasswordBox[] boxes)
    {
        foreach (PasswordBox box in boxes)
        {
            box.Password = string.Empty;
        }
    }

    private void ClearCard()
    {
        this.snapshot = null;
        this.CardPanel.Visibility = Visibility.Collapsed;
        this.ManagementPanel.IsHitTestVisible = false;
        this.ManagementPanel.Opacity = 0.6;
    }

    private void SetBusy(bool busy)
    {
        this.busy = busy;
        this.ActionRoot.IsHitTestVisible = !busy;
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
