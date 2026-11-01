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

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.Storage;
using Windows.Storage.Pickers;
using WinRT.Interop;

/// <summary>Verifies a signed document, or signs one with the card.</summary>
internal sealed partial class DocumentPage : Page
{
    /// <summary>The PIN lengths the card accepts.</summary>
    private const int PinMinimumLength = 4;
    private const int PinMaximumLength = 12;

    /// <summary>The reason bytes the native service accepts.</summary>
    private const int ReasonMaximumBytes = 256;

    /// <summary>How often the page looks for a card in a reader here.</summary>
    private static readonly TimeSpan CardPollInterval = TimeSpan.FromSeconds(2);

    private readonly DispatcherTimer cardPollTimer;
    private DocumentMode mode;
    private bool busy;
    private bool polling;

    public DocumentPage()
    {
        this.InitializeComponent();
        this.cardPollTimer = new DispatcherTimer { Interval = CardPollInterval };
        this.cardPollTimer.Tick += (s, e) => this.PollCard();
        this.Loaded += this.OnLoaded;
        this.Unloaded += this.OnUnloaded;
    }

    private void OnLoaded(object sender, RoutedEventArgs args)
    {
        this.PollCard();
        this.cardPollTimer.Start();
    }

    private void OnUnloaded(object sender, RoutedEventArgs args) => this.cardPollTimer.Stop();

    /// <summary>
    /// The PIN box shows while a reader here holds a card; without one the
    /// paired phone signs and takes PIN 2 on its own screen.
    /// </summary>
    private async void PollCard()
    {
        if (this.busy || this.polling)
        {
            return;
        }

        this.polling = true;
        try
        {
            bool cardHere = await Task.Run(LocalCardService.CardInAReader).ConfigureAwait(true);
            this.ShowPinBox(cardHere);
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
#if DEBUG
            DevErrorLog.Report("card service not loaded", error);
#endif
        }
        finally
        {
            this.polling = false;
        }
    }

    private void ShowPinBox(bool cardHere)
    {
        if (!cardHere)
        {
            this.PinBox.Password = string.Empty;
        }

        this.PinBox.Visibility = cardHere ? Visibility.Visible : Visibility.Collapsed;
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        this.mode = e.Parameter is DocumentMode requested ? requested : DocumentMode.Verify;
        bool signing = this.mode == DocumentMode.Sign;
        this.TitleText.Text = Strings.Get(signing ? "DocumentSignTitle" : "DocumentVerifyTitle");
        this.SignPanel.Visibility = signing ? Visibility.Visible : Visibility.Collapsed;
        this.VerifyButton.Visibility = signing ? Visibility.Collapsed : Visibility.Visible;
        this.UpdateActions();
    }

    private async void ChooseFileButton_Click(object sender, RoutedEventArgs args)
    {
        if (this.busy || App.MainWindow is not Window window)
        {
            return;
        }

        FileOpenPicker picker = new()
        {
            SuggestedStartLocation = PickerLocationId.DocumentsLibrary,
        };
        if (this.mode == DocumentMode.Sign && this.FormatBox.SelectedIndex == 0)
        {
            picker.FileTypeFilter.Add(".pdf");
        }
        else
        {
            picker.FileTypeFilter.Add("*");
        }

        StorageFile? file;
        try
        {
            InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));
            file = await picker.PickSingleFileAsync();
        }
        catch (Exception error) when (error is COMException or InvalidOperationException)
        {
#if DEBUG
            DevErrorLog.Report("file chooser not opened", error);
#endif
            this.ShowStatus(InfoBarSeverity.Error, Strings.Get("FileChooserNotOpened"));
            return;
        }

        if (file is not null)
        {
            this.FileBox.Text = file.Path;
            this.ClearOutcome();
            this.UpdateActions();
        }
    }

    private async void VerifyButton_Click(object sender, RoutedEventArgs args)
    {
        if (this.busy || !this.TryGetFile(out string path))
        {
            return;
        }

        await this.RunAsync(async () =>
            {
                ContainerVerifyReport report = await Task.Run(() =>
                        LocalCardService.VerifyContainer(path)
                    )
                    .ConfigureAwait(true);
                this.ResultText.Text = report.Report;
                this.ShowStatus(
                    report.Ok ? InfoBarSeverity.Success : InfoBarSeverity.Error,
                    Strings.Get(report.Ok ? "SignatureValid" : "SignatureInvalid")
                );
            })
            .ConfigureAwait(true);
    }

    private async void SignButton_Click(object sender, RoutedEventArgs args)
    {
        if (this.busy || !this.TryGetFile(out string path))
        {
            return;
        }

        DocumentFormat format =
            this.FormatBox.SelectedIndex == 1 ? DocumentFormat.AsicE : DocumentFormat.Pades;
        string reason = this.ReasonBox.Text;
        this.ClearOutcome();
        if (Encoding.UTF8.GetByteCount(reason) > ReasonMaximumBytes)
        {
            this.ShowStatus(InfoBarSeverity.Warning, Strings.Get("ReasonTooLong"));
            return;
        }

        await this.RunAsync(async () =>
            {
                // A card in a reader attached to this computer signs under the
                // PIN typed here; without one the paired phone signs and asks
                // for PIN 2 on its own screen, and no PIN is read here.
                bool cardHere = await Task.Run(LocalCardService.CardInAReader).ConfigureAwait(true);
                this.ShowPinBox(cardHere);
                string? pin = cardHere ? this.PinBox.Password : null;
                if (pin is not null && !IsPin(pin))
                {
                    this.ShowStatus(
                        InfoBarSeverity.Warning,
                        Strings.Format("Pin2LengthRule", PinMinimumLength, PinMaximumLength)
                    );
                    return;
                }

                DocumentSignReport report;
                try
                {
                    report = await Task.Run(() =>
                            LocalCardService.SignDocument(path, format, pin, reason)
                        )
                        .ConfigureAwait(true);
                }
                finally
                {
                    this.PinBox.Password = string.Empty;
                }

                this.ResultText.Text =
                    Strings.Format(
                        "SignedDocumentSummary",
                        report.OutputPath,
                        report.OutputLength,
                        report.LocalVerify
                    ) + (report.SignerCommonName is string signer ? $"\n{signer}" : string.Empty);
                if (report.Verified)
                {
                    this.ShowStatus(InfoBarSeverity.Success, Strings.Get("DocumentSigned"));
                }
                else
                {
                    this.ShowStatus(
                        InfoBarSeverity.Error,
                        Strings.Format("SignatureDidNotVerify", report.OutputPath)
                    );
                }
            })
            .ConfigureAwait(true);
    }

    /// <summary>Whether the typed PIN is digits of a length the card accepts.</summary>
    private static bool IsPin(string pin) =>
        pin.Length >= PinMinimumLength
        && pin.Length <= PinMaximumLength
        && pin.All(character => character is >= '0' and <= '9');

    private bool TryGetFile(out string path)
    {
        path = this.FileBox.Text;
        if (path.Length > 0)
        {
            return true;
        }

        this.ShowStatus(InfoBarSeverity.Warning, Strings.Get("ChooseFileFirst"));
        return false;
    }

    [SuppressMessage(
        "Design",
        "CA1031:Do not catch general exception types",
        Justification = "An exception that leaves an async void handler ends the process; the page shows it."
    )]
    private async Task RunAsync(Func<Task> operation)
    {
        if (this.busy)
        {
            return;
        }

        this.ClearOutcome();
        this.SetBusy(true);
        try
        {
            await operation().ConfigureAwait(true);
        }
        catch (NativeRappException error)
        {
            this.ShowStatus(InfoBarSeverity.Error, error.Message);
        }
        catch (JsonException)
        {
            this.ShowStatus(InfoBarSeverity.Error, Strings.Get("CardServiceResponseUnreadable"));
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
#if DEBUG
            DevErrorLog.Report("card service not loaded", error);
#endif
            this.ShowStatus(InfoBarSeverity.Error, Strings.Get("CardServiceNotInstalled"));
        }
        // codeql[cs/catch-of-all-exceptions]
        catch (Exception error)
        {
#if DEBUG
            DevErrorLog.Report("document action failed", error);
#endif
            this.ShowStatus(InfoBarSeverity.Error, error.Message);
        }
        finally
        {
            this.SetBusy(false);
        }
    }

    private void ClearOutcome()
    {
        this.StatusInfoBar.IsOpen = false;
        this.ResultText.Text = string.Empty;
    }

    private void SetBusy(bool busy)
    {
        this.busy = busy;
        this.ActionRoot.IsHitTestVisible = !busy;
        this.BusyOverlay.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
        this.BusyOverlay.IsHitTestVisible = busy;
        this.UpdateActions();
    }

    /// <summary>Sign and Verify act only on a chosen file, one operation at a time.</summary>
    private void UpdateActions()
    {
        bool ready = !this.busy && this.FileBox.Text.Length > 0;
        this.SignButton.IsEnabled = ready;
        this.VerifyButton.IsEnabled = ready;
    }

    private void ShowStatus(InfoBarSeverity severity, string message)
    {
        this.StatusInfoBar.Severity = severity;
        this.StatusInfoBar.Message = message;
        this.StatusInfoBar.IsOpen = true;
    }
}
