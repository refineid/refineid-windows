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
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

/// <summary>
/// The PIN page: PIN change and reset, activation, and the contactless
/// CAN for the card in the reader, with no more on screen than the task
/// at hand. A card that still waits for its activation shows the activation
/// section alone, opened; an activated card shows PIN change and reset;
/// a card whose state the probes did not decide shows every section.
/// Every modifying command is bound to the inspected reader and card
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

    /// <summary>The reader the main screen opened this page for, used once.</summary>
    private string? requestedReader;

    /// <summary>The main screen's inspection of that reader's card, shown once on loading.</summary>
    private LocalCardSnapshot? handedOver;

    /// <summary>Whether the activation section was shown at the last inspection.</summary>
    private bool activationShown;

    /// <summary>
    /// The digit counts a new PIN may have, as the card service's PIN
    /// types bound them: PIN 1 takes four to twelve digits, PIN 2 six to
    /// twelve.
    /// </summary>
    private const int Pin1MinimumDigits = 4;
    private const int Pin2MinimumDigits = 6;
    private const int PinMaximumDigits = 12;

    /// <summary>Segoe Fluent Icons: CheckMark, Cancel and Warning.</summary>
    private const string ValidGlyph = "\uE73E";
    private const string InvalidGlyph = "\uE711";
    private const string DifferGlyph = "\uE7BA";

    public CardPage()
    {
        this.InitializeComponent();
        this.ChangeSlotBox.SelectionChanged += (s, e) =>
            LabelPinFields(this.ChangeSlotBox, this.NewPinBox, this.NewPinConfirmationBox);
        this.UnblockSlotBox.SelectionChanged += (s, e) =>
            LabelPinFields(this.UnblockSlotBox, this.UnblockNewPinBox, this.UnblockConfirmationBox);
        LabelPinFields(this.ChangeSlotBox, this.NewPinBox, this.NewPinConfirmationBox);
        LabelPinFields(this.UnblockSlotBox, this.UnblockNewPinBox, this.UnblockConfirmationBox);
        this.readerPollTimer = new DispatcherTimer { Interval = ReaderPollInterval };
        this.readerPollTimer.Tick += (s, e) => this.PollReaders();
        this.Loaded += this.OnLoaded;
        this.Unloaded += this.OnUnloaded;
    }

    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        if (this.handedOver is LocalCardSnapshot inspected)
        {
            this.handedOver = null;
            this.ShowInspected(inspected);
        }

        await this.RefreshReadersAsync().ConfigureAwait(true);
        this.readerPollTimer.Start();
    }

    private void OnUnloaded(object sender, RoutedEventArgs args) => this.readerPollTimer.Stop();

    /// <summary>
    /// The main screen names the reader whose card it inspected, or hands
    /// over that inspection, which decides the page before its first draw.
    /// </summary>
    protected override void OnNavigatedTo(NavigationEventArgs args)
    {
        base.OnNavigatedTo(args);
        if (args.Parameter is LocalCardSnapshot inspected)
        {
            this.requestedReader = inspected.Reader;
            this.handedOver = inspected;
        }
        else
        {
            this.requestedReader = args.Parameter as string;
        }
    }

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
            this.ShowError(Strings.Get("SelectReaderWithCardFirst"));
            return;
        }

        string can = this.CanBox.Password;
        this.CanBox.Password = string.Empty;
        await this.RunCardOperationAsync(async () =>
            {
                _ = await Task.Run(() => LocalCardService.PrimeContactless(reader, can))
                    .ConfigureAwait(true);
                this.ShowSuccess(Strings.Get("NfcAccessEnabled"));
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

    /// <summary>
    /// Every activation entry keeps digits only and refreshes the marks
    /// and the button as it is typed, so a wrong length or a mismatch
    /// shows before anything is sent to the card.
    /// </summary>
    private void ActivationEntry_Changed(object sender, RoutedEventArgs args)
    {
        if (sender is PasswordBox box)
        {
            string digits = new(box.Password.Where(char.IsAsciiDigit).ToArray());
            if (!string.Equals(digits, box.Password, StringComparison.Ordinal))
            {
                box.Password = digits;
                return;
            }
        }

        this.UpdateActivationForm();
    }

    /// <summary>
    /// Marks each entry valid, invalid or differing from its pair, and
    /// enables the button only when the activation code has the card's
    /// length and each new PIN the card asks for is valid and repeated.
    /// The form asks only for the PINs that wait for their activation.
    /// </summary>
    private void UpdateActivationForm()
    {
        bool askPin1 = this.snapshot?.Pin1AwaitsActivation ?? true;
        bool askPin2 = this.snapshot?.Pin2AwaitsActivation ?? true;
        this.ActivationPin1Group.Visibility = askPin1 ? Visibility.Visible : Visibility.Collapsed;
        this.ActivationPin2Group.Visibility = askPin2 ? Visibility.Visible : Visibility.Collapsed;

        string code = this.ActivationCodeBox.Password;
        string pin1 = this.ActivationPin1Box.Password;
        string pin1Again = this.ActivationPin1ConfirmationBox.Password;
        string pin2 = this.ActivationPin2Box.Password;
        string pin2Again = this.ActivationPin2ConfirmationBox.Password;

        bool codeValid = this.snapshot?.ActivationCodeLength is int length && code.Length == length;
        bool pin1Valid = IsPinLength(pin1, Pin1MinimumDigits);
        bool pin1Repeated = pin1Valid && string.Equals(pin1Again, pin1, StringComparison.Ordinal);
        bool pin1Differs = pin1Valid && IsPinLength(pin1Again, Pin1MinimumDigits) && !pin1Repeated;
        bool pin2Valid = IsPinLength(pin2, Pin2MinimumDigits);
        bool pin2Repeated = pin2Valid && string.Equals(pin2Again, pin2, StringComparison.Ordinal);
        bool pin2Differs = pin2Valid && IsPinLength(pin2Again, Pin2MinimumDigits) && !pin2Repeated;

        Mark(this.ActivationCodeBoxMark, codeValid, differs: false, isEmpty: code.Length == 0);
        Mark(this.ActivationPin1BoxMark, pin1Valid, differs: false, isEmpty: pin1.Length == 0);
        Mark(
            this.ActivationPin1ConfirmationBoxMark,
            pin1Repeated,
            pin1Differs,
            pin1Again.Length == 0
        );
        Mark(this.ActivationPin2BoxMark, pin2Valid, differs: false, isEmpty: pin2.Length == 0);
        Mark(
            this.ActivationPin2ConfirmationBoxMark,
            pin2Repeated,
            pin2Differs,
            pin2Again.Length == 0
        );
        this.ActivateButton.IsEnabled =
            codeValid && (!askPin1 || pin1Repeated) && (!askPin2 || pin2Repeated);
    }

    private static bool IsPinLength(string entry, int minimumDigits) =>
        entry.Length >= minimumDigits && entry.Length <= PinMaximumDigits;

    /// <summary>
    /// A green check, a red cross, or an amber warning for a pair that
    /// differs, each named for a screen reader. A theme without the brush
    /// leaves the mark in the text colour.
    /// </summary>
    private static void Mark(FontIcon mark, bool valid, bool differs, bool isEmpty)
    {
        mark.Visibility = isEmpty ? Visibility.Collapsed : Visibility.Visible;
        string brush;
        string description;
        if (valid)
        {
            mark.Glyph = ValidGlyph;
            brush = "SystemFillColorSuccessBrush";
            description = "EntryValid";
        }
        else if (differs)
        {
            mark.Glyph = DifferGlyph;
            brush = "SystemFillColorCautionBrush";
            description = "EntriesDiffer";
        }
        else
        {
            mark.Glyph = InvalidGlyph;
            brush = "SystemFillColorCriticalBrush";
            description = "EntryInvalid";
        }

        AutomationProperties.SetName(mark, Strings.Get(description));
        if (
            Application.Current.Resources.TryGetValue(brush, out object? resource)
            && resource is Brush found
        )
        {
            mark.Foreground = found;
        }
    }

    private async void ActivateButton_Click(object sender, RoutedEventArgs args)
    {
        if (!this.TryGetBoundCard(out string reader, out string serial))
        {
            return;
        }

        // A PIN the card does not ask for goes out empty, so nothing the
        // holder cannot see is sent.
        bool askPin1 = this.snapshot?.Pin1AwaitsActivation ?? true;
        bool askPin2 = this.snapshot?.Pin2AwaitsActivation ?? true;
        string activationCode = this.ActivationCodeBox.Password;
        string pin1 = askPin1 ? this.ActivationPin1Box.Password : string.Empty;
        string pin1Confirmation = askPin1
            ? this.ActivationPin1ConfirmationBox.Password
            : string.Empty;
        string pin2 = askPin2 ? this.ActivationPin2Box.Password : string.Empty;
        string pin2Confirmation = askPin2
            ? this.ActivationPin2ConfirmationBox.Password
            : string.Empty;
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

        string? previous = this.SelectedReader() ?? this.requestedReader;
        this.requestedReader = null;
        await this.RunCardOperationAsync(async () =>
            {
                IReadOnlyList<string> readers = await Task.Run(LocalCardService.PresentReaders)
                    .ConfigureAwait(true);
                this.refreshingReaders = true;
                try
                {
                    this.ReaderComboBox.Visibility =
                        readers.Count > 1 ? Visibility.Visible : Visibility.Collapsed;
                    this.ReaderComboBox.ItemsSource = readers;
                    this.ReaderComboBox.SelectedItem =
                        previous is not null && readers.Contains(previous, StringComparer.Ordinal)
                            ? previous
                        : readers.Count > 0 ? readers[0]
                        : null;
                }
                finally
                {
                    this.refreshingReaders = false;
                }

                if (readers.Count == 0)
                {
                    // Without a card there is nothing to do here; the main
                    // screen takes over, as it does on a first launch.
                    this.ClearCard();
                    this.StatusInfoBar.IsOpen = false;
                    if (this.Frame.CanGoBack)
                    {
                        this.Frame.GoBack();
                    }

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
        // Entries typed for one card do not carry over to another.
        if (!string.Equals(this.snapshot?.Serial, inspected.Serial, StringComparison.Ordinal))
        {
            Clear(
                this.ActivationCodeBox,
                this.ActivationPin1Box,
                this.ActivationPin1ConfirmationBox,
                this.ActivationPin2Box,
                this.ActivationPin2ConfirmationBox
            );
        }

        this.ShowInspected(inspected);
        this.StatusInfoBar.IsOpen = false;
    }

    /// <summary>The page for an inspected card: its sections, heading and form.</summary>
    private void ShowInspected(LocalCardSnapshot inspected)
    {
        this.snapshot = inspected;
        // The code box takes no more digits than the card's code has.
        if (inspected.ActivationCodeLength is int codeLength)
        {
            this.ActivationCodeBox.MaxLength = codeLength;
        }

        this.UpdateActivationForm();
        this.ManagementPanel.IsHitTestVisible = true;
        this.ManagementPanel.Opacity = 1;
        this.ShowActivationState(inspected);
    }

    /// <summary>
    /// A contactless card without a stored access number: only the entry
    /// that primes it; nothing else on the page applies before that.
    /// </summary>
    private void ShowContactlessPrimingOnly()
    {
        this.NfcExpander.Visibility = Visibility.Visible;
        this.ChangePinExpander.Visibility = Visibility.Collapsed;
        this.UnblockPinExpander.Visibility = Visibility.Collapsed;
        this.ActivationPanel.Visibility = Visibility.Collapsed;
    }

    /// <summary>
    /// A card that waits for its activation gets the activation section
    /// alone, opened: activation sets both PINs, so a PIN change, reset or
    /// contactless setup has no place before it. An activated card gets
    /// those, and the activation section goes, since the card service
    /// refuses activation on it. An inspected card in an unknown state
    /// shows every section. Without an inspected card nothing that depends
    /// on the card is shown; the heading is named from the same inspection
    /// that shows the section. The activation section takes the focus only
    /// when it appears, so a re-inspection while the holder types, or after
    /// a refused attempt, leaves the focus alone.
    /// </summary>
    private void ShowActivationState(LocalCardSnapshot? inspected)
    {
        if (inspected is null)
        {
            this.NfcExpander.Visibility = Visibility.Collapsed;
            this.ChangePinExpander.Visibility = Visibility.Collapsed;
            this.UnblockPinExpander.Visibility = Visibility.Collapsed;
            this.ActivationPanel.Visibility = Visibility.Collapsed;
            this.activationShown = false;
            return;
        }

        bool unactivated = inspected.LooksUnactivated;
        bool activated = inspected.LooksActivated;
        string title = Strings.Get(
            inspected.OrganizationCard
                ? "OrganisationCardActivationHeading"
                : "IdentityCardActivationHeading"
        );
        this.ActivationHeading.Text = title;
        AutomationProperties.SetName(this.ActivationPanel, title);
        Visibility managing = unactivated ? Visibility.Collapsed : Visibility.Visible;
        this.NfcExpander.Visibility = managing;
        this.ChangePinExpander.Visibility = managing;
        this.UnblockPinExpander.Visibility = managing;
        this.ActivationPanel.Visibility = activated ? Visibility.Collapsed : Visibility.Visible;
        if (unactivated && !this.activationShown)
        {
            _ = this.ActivationCodeBox.Focus(FocusState.Programmatic);
        }

        this.activationShown = unactivated;
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
        catch (NativeRappException error) when (error.Code == "access_number_required")
        {
            // A card on the contactless antenna, not yet primed: the page's
            // contactless entry is the way in, alone and without a notice.
            this.StatusInfoBar.IsOpen = false;
            this.ShowContactlessPrimingOnly();
        }
        catch (NativeRappException error)
        {
            this.ShowError(error.Message);
        }
        catch (JsonException)
        {
            this.ShowError(Strings.Get("CardServiceResponseUnreadable"));
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

        this.ShowError(Strings.Get("InsertCardInContactReaderFirst"));
        return false;
    }

    private string? SelectedReader() => this.ReaderComboBox.SelectedItem as string;

    private static PinSlot SlotFrom(ComboBox box) =>
        box.SelectedIndex == 1 ? PinSlot.Pin2 : PinSlot.Pin1;

    /// <summary>
    /// Names the new-PIN field and its repeat after the PIN the slot box
    /// holds: "New basic PIN 1" and "Repeat PIN 1", or the PIN 2 pair.
    /// </summary>
    private static void LabelPinFields(ComboBox slotBox, PasswordBox newBox, PasswordBox repeatBox)
    {
        bool pin2 = SlotFrom(slotBox) == PinSlot.Pin2;
        string newLabel = Strings.Get(pin2 ? "NewPin2Field" : "NewPin1Field");
        string repeatLabel = Strings.Get(pin2 ? "RepeatPin2Field" : "RepeatPin1Field");
        newBox.Header = newLabel;
        AutomationProperties.SetName(newBox, newLabel);
        repeatBox.Header = repeatLabel;
        AutomationProperties.SetName(repeatBox, repeatLabel);
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
        this.ManagementPanel.IsHitTestVisible = false;
        this.ManagementPanel.Opacity = 0.6;
        this.ShowActivationState(null);
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
