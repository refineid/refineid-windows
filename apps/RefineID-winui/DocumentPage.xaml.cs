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

    private DocumentMode mode;
    private bool busy;

    public DocumentPage()
    {
        this.InitializeComponent();
    }

    protected override void OnNavigatedTo(NavigationEventArgs e)
    {
        base.OnNavigatedTo(e);
        this.mode = e.Parameter is DocumentMode requested ? requested : DocumentMode.Verify;
        bool signing = this.mode == DocumentMode.Sign;
        this.TitleText.Text = signing ? "Sign" : "Verify";
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
            this.ShowStatus(InfoBarSeverity.Error, "The file chooser could not be opened.");
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
                    report.Ok ? "Valid" : "Invalid"
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
        string pin = this.PinBox.Password;
        string reason = this.ReasonBox.Text;
        this.ClearOutcome();
        if (!IsPin(pin))
        {
            this.ShowStatus(
                InfoBarSeverity.Warning,
                $"PIN 2 is {PinMinimumLength} to {PinMaximumLength} digits."
            );
            return;
        }

        if (Encoding.UTF8.GetByteCount(reason) > ReasonMaximumBytes)
        {
            this.ShowStatus(InfoBarSeverity.Warning, "The reason is too long.");
            return;
        }

        await this.RunAsync(async () =>
            {
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
                    $"{report.OutputPath}\n{report.OutputLength} bytes, qualified signature, local verify {report.LocalVerify}"
                    + (report.SignerCommonName is string signer ? $"\n{signer}" : string.Empty);
                if (report.Verified)
                {
                    this.ShowStatus(InfoBarSeverity.Success, "Signed");
                }
                else
                {
                    this.ShowStatus(
                        InfoBarSeverity.Error,
                        $"{report.OutputPath}: the signature did not verify"
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

        this.ShowStatus(InfoBarSeverity.Warning, "Choose a file first.");
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
            this.ShowStatus(InfoBarSeverity.Error, "The card service response could not be read.");
        }
        catch (Exception error) when (error is DllNotFoundException or EntryPointNotFoundException)
        {
#if DEBUG
            DevErrorLog.Report("card service not loaded", error);
#endif
            this.ShowStatus(InfoBarSeverity.Error, "The card service is not installed.");
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
