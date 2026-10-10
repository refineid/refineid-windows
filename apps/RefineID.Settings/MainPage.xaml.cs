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

using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace RefineID_Settings;

public sealed partial class MainPage : Page
{
    private CardSnapshot? _snapshot;
    private bool _busy;
    private bool _refreshingReaders;
    private bool _polling;

    // Card-present readers are listed on this cadence so inserted, removed and
    // tapped cards appear without user action.
    private static readonly TimeSpan ReaderPollInterval = TimeSpan.FromSeconds(2);

    private readonly DispatcherTimer _readerPollTimer = new() { Interval = ReaderPollInterval };

    public MainPage()
    {
        InitializeComponent();
        _readerPollTimer.Tick += ReaderPollTimer_Tick;
        Unloaded += (_, _) => _readerPollTimer.Stop();
    }

    private async void Page_Loaded(object sender, RoutedEventArgs e)
    {
        await RefreshReadersAsync();
        _readerPollTimer.Start();
    }

    // A tick lists readers only; the card is inspected again only when the set
    // of card-present readers changes.
    private async void ReaderPollTimer_Tick(object? sender, object e)
    {
        if (_busy || _polling)
        {
            return;
        }

        _polling = true;
        try
        {
            string[] readers = await Task.Run(NativeCardService.PresentReaders);
            string[] shown = ReaderComboBox.ItemsSource as string[] ?? [];
            if (!_busy && !readers.SequenceEqual(shown, StringComparer.Ordinal))
            {
                await RefreshReadersAsync();
            }
        }
        // codeql[cs/catch-of-all-exceptions]
        catch (Exception)
        {
            // The next tick retries. Errors are shown only by a full refresh.
        }
        finally
        {
            _polling = false;
        }
    }

    private async void ReaderComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_refreshingReaders || _busy)
        {
            return;
        }

        await InspectSelectedReaderAsync();
    }

    private async void EnableNfcButton_Click(object sender, RoutedEventArgs e)
    {
        string? reader = SelectedReader();
        if (reader is null)
        {
            ShowError("Select a card-present reader first.");
            return;
        }

        string can = CanBox.Password;
        CanBox.Password = string.Empty;
        await RunCardOperationAsync(async () =>
        {
            ContactlessSnapshot snapshot = await Task.Run(() =>
                NativeCardService.PrimeContactless(reader, can)
            );
            NfcResultText.Text =
                $"Secure NFC channel opened for {DisplayPerson(snapshot.Person)}. "
                + $"Card serial: {snapshot.Serial}. "
                + $"PIN1: {FormatStatus(snapshot.Pin1)}; "
                + $"PIN2: {FormatStatus(snapshot.Pin2)}; "
                + "recovery: not queried over NFC.";
            NfcResultPanel.Visibility = Visibility.Visible;
            ShowSuccess(
                "Contactless access enabled",
                "PACE succeeded and the CAN was saved in Windows Credential Manager."
            );
        });
    }

    private async void ChangePinButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryGetBoundCard(out string reader, out string serial))
        {
            return;
        }

        PinSlot slot = SlotFrom(ChangeSlotBox);
        string current = CurrentPinBox.Password;
        string next = NewPinBox.Password;
        string confirmation = NewPinConfirmationBox.Password;
        Clear(CurrentPinBox, NewPinBox, NewPinConfirmationBox);

        await RunMutationAsync(() =>
            NativeCardService.ChangePin(reader, serial, slot, current, next, confirmation)
        );
    }

    private async void UnblockPinButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryGetBoundCard(out string reader, out string serial))
        {
            return;
        }

        PinSlot slot = SlotFrom(UnblockSlotBox);
        string puk = PukBox.Password;
        string next = UnblockNewPinBox.Password;
        string confirmation = UnblockConfirmationBox.Password;
        Clear(PukBox, UnblockNewPinBox, UnblockConfirmationBox);

        await RunMutationAsync(() =>
            NativeCardService.UnblockPin(reader, serial, slot, puk, next, confirmation)
        );
    }

    private async void ActivateButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryGetBoundCard(out string reader, out string serial))
        {
            return;
        }

        string activationCode = ActivationCodeBox.Password;
        string pin1 = ActivationPin1Box.Password;
        string pin1Confirmation = ActivationPin1ConfirmationBox.Password;
        string pin2 = ActivationPin2Box.Password;
        string pin2Confirmation = ActivationPin2ConfirmationBox.Password;
        Clear(
            ActivationCodeBox,
            ActivationPin1Box,
            ActivationPin1ConfirmationBox,
            ActivationPin2Box,
            ActivationPin2ConfirmationBox
        );

        await RunMutationAsync(() =>
            NativeCardService.Activate(
                reader,
                serial,
                activationCode,
                pin1,
                pin1Confirmation,
                pin2,
                pin2Confirmation,
                allowReactivate: false
            )
        );
    }

    private async Task RefreshReadersAsync()
    {
        if (_busy)
        {
            return;
        }

        string? previous = SelectedReader();
        await RunCardOperationAsync(async () =>
        {
            string[] readers = await Task.Run(NativeCardService.PresentReaders);
            _refreshingReaders = true;
            try
            {
                ReaderComboBox.ItemsSource = readers;
                ReaderComboBox.SelectedItem =
                    previous is not null && readers.Contains(previous, StringComparer.Ordinal)
                        ? previous
                        : readers.FirstOrDefault();
            }
            finally
            {
                _refreshingReaders = false;
            }

            if (readers.Length == 0)
            {
                ClearCard();
                LocalCardSupport support = await Task.Run(NativeCardService.DetectLocalCardSupport);
                if (support.State == "driver_not_installed")
                {
                    ShowNotice(
                        "FINEID drivers not detected",
                        "The local FINEID card stack is not installed. Visit https://pkg.refineid.fi/drivers to get it. Phone-powered Remote Reader remains available."
                    );
                    return;
                }

                StatusInfoBar.IsOpen = false;
                return;
            }

            await InspectSelectedReaderCoreAsync();
        });
    }

    private async Task InspectSelectedReaderAsync()
    {
        if (SelectedReader() is null)
        {
            ClearCard();
            return;
        }

        await RunCardOperationAsync(InspectSelectedReaderCoreAsync);
    }

    private async Task InspectSelectedReaderCoreAsync()
    {
        await InspectSelectedReaderCoreAsync(showReadyMessage: true);
    }

    private async Task InspectSelectedReaderCoreAsync(bool showReadyMessage)
    {
        string? reader = SelectedReader();
        if (reader is null)
        {
            ClearCard();
            return;
        }

        CardSnapshot snapshot = await Task.Run(() => NativeCardService.Inspect(reader));
        _snapshot = snapshot;
        PersonText.Text = DisplayPerson(snapshot.Person);
        ModelText.Text = snapshot.Model;
        SerialText.Text = snapshot.Serial;
        Pin1StatusText.Text = FormatStatus(snapshot.Pin1, snapshot.Pin1Changed);
        Pin2StatusText.Text = FormatStatus(snapshot.Pin2, snapshot.Pin2Changed);
        PukStatusText.Text = FormatStatus(snapshot.Puk);
        GenerationText.Text = snapshot.Generation switch
        {
            "newer" => "Current single-use activation scheme",
            "older" => "Legacy reusable activation scheme",
            _ => "Unknown",
        };
        ActivationHintText.Text = snapshot.ActivationCodeLength is int length
            ? $"{length}-digit activation code."
            : "Unknown activation code. Activation refused.";
        CardPanel.Visibility = Visibility.Visible;
        ManagementPanel.IsHitTestVisible = true;
        ManagementPanel.Opacity = 1;
        if (showReadyMessage)
        {
            ShowSuccess("Card ready", "The card passed the local trust and serial-binding checks.");
        }
    }

    private async Task RunMutationAsync(Func<MutationResult> operation)
    {
        await RunCardOperationAsync(async () =>
        {
            MutationResult result = await Task.Run(operation);
            await InspectSelectedReaderCoreAsync(showReadyMessage: false);
            if (result.Succeeded)
            {
                ShowSuccess("Card updated", result.Message);
            }
            else
            {
                ShowWarning("The card was not updated", result.Message);
            }
        });
    }

    private async Task RunCardOperationAsync(Func<Task> operation)
    {
        if (_busy)
        {
            return;
        }

        SetBusy(true);
        try
        {
            await operation();
        }
        catch (NativeCardException error)
        {
            ShowError(error.Message);
        }
        // codeql[cs/catch-of-all-exceptions]
        catch (Exception)
        {
            ShowError(string.Empty);
        }
        finally
        {
            SetBusy(false);
        }
    }

    private bool TryGetBoundCard(out string reader, out string serial)
    {
        reader = SelectedReader() ?? string.Empty;
        serial = _snapshot?.Serial ?? string.Empty;
        if (reader.Length > 0 && serial.Length > 0)
        {
            return true;
        }

        ShowError("Inspect a contact card before starting a management operation.");
        return false;
    }

    private string? SelectedReader()
    {
        return ReaderComboBox.SelectedItem as string;
    }

    private static PinSlot SlotFrom(ComboBox box)
    {
        return box.SelectedIndex == 1 ? PinSlot.Pin2 : PinSlot.Pin1;
    }

    private static string DisplayPerson(string person)
    {
        return string.IsNullOrWhiteSpace(person) ? "Not available" : person;
    }

    private static string FormatStatus(CredentialStatus? status, bool? changed = null)
    {
        if (status is null)
        {
            return "Not available";
        }

        string value = status.State switch
        {
            "verified" => "Verified in the current card session",
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
        _snapshot = null;
        CardPanel.Visibility = Visibility.Collapsed;
        ManagementPanel.IsHitTestVisible = false;
        ManagementPanel.Opacity = 0.6;
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        ActionRoot.IsHitTestVisible = !busy;
        BusyOverlay.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
    }

    private void ShowSuccess(string title, string message)
    {
        ShowStatus(InfoBarSeverity.Success, title, message);
    }

    private void ShowNotice(string title, string message)
    {
        ShowStatus(InfoBarSeverity.Informational, title, message);
    }

    private void ShowWarning(string title, string message)
    {
        ShowStatus(InfoBarSeverity.Warning, title, message);
    }

    private void ShowError(string message)
    {
        ShowStatus(InfoBarSeverity.Error, "Card operation failed", message);
    }

    private void ShowStatus(InfoBarSeverity severity, string title, string message)
    {
        StatusInfoBar.Severity = severity;
        StatusInfoBar.Title = title;
        StatusInfoBar.Message = message;
        StatusInfoBar.IsOpen = true;
    }
}
