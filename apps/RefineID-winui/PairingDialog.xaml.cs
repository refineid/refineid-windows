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

using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;
using QRCoder;
using Windows.Storage.Streams;

/// <summary>
/// Presents one pairing offer as a QR code, polls its progress, hosts the
/// on-screen confirmation, and reports the paired handle or the failure.
/// </summary>
internal sealed partial class PairingDialog : ContentDialog
{
    private const int QrPixelsPerModule = 8;

    private readonly ulong handle;
    private readonly DispatcherQueueTimer timer;
    private bool confirmed;
    private bool settled;

    /// <summary>The handle once the pairing completed, otherwise null.</summary>
    public ulong? PairedHandle { get; private set; }

    /// <summary>A human-readable failure, set when pairing did not complete.</summary>
    public string? Failure { get; private set; }

    private readonly string offerUri;
    private readonly string pairingCode;

    public PairingDialog(
        ulong handle,
        string offerUri,
        string pairingCode,
        DispatcherQueue dispatcher,
        TimeSpan pollInterval
    )
    {
        this.InitializeComponent();
        this.handle = handle;
        this.offerUri = offerUri;
        this.pairingCode = pairingCode;
        if (!string.IsNullOrWhiteSpace(pairingCode))
        {
            this.PairingCodeText.Text = pairingCode;
        }
        else
        {
            this.PairingCodeText.Visibility = Visibility.Collapsed;
        }

        this.timer = dispatcher.CreateTimer();
        this.timer.Interval = pollInterval;
        this.timer.Tick += this.OnPoll;
        this.timer.Start();

        this.Loaded += this.OnLoaded;
        this.Closing += this.OnClosing;
    }

    private async void OnLoaded(object sender, RoutedEventArgs args)
    {
        this.Loaded -= this.OnLoaded;
        this.QrImage.Source = await RenderQrAsync(this.offerUri).ConfigureAwait(true);
    }

    private static async Task<BitmapImage> RenderQrAsync(string text)
    {
        byte[] bytes = BuildQrPng(text);
        var image = new BitmapImage();
        using var stream = new InMemoryRandomAccessStream();
        await stream.WriteAsync(bytes.AsBuffer());
        stream.Seek(0);
        await image.SetSourceAsync(stream);
        return image;
    }

    private static byte[] BuildQrPng(string text)
    {
        using var generator = new QRCodeGenerator();
        using QRCodeData data = generator.CreateQrCode(text, QRCodeGenerator.ECCLevel.M);
        using var png = new PngByteQRCode(data);
        return png.GetGraphic(QrPixelsPerModule);
    }

    private void OnPoll(DispatcherQueueTimer sender, object args)
    {
        PairingState state;
        try
        {
            state = NativeRappService.PollPairing(this.handle);
        }
        catch (NativeRappException error)
        {
            this.Settle(failure: error.Message);
            return;
        }

        switch (state.State)
        {
            case "awaiting_confirmation":
                this.AutoConfirm(state.Peer);
                break;
            case "paired":
                this.PairedHandle = this.handle;
                this.Settle(failure: null);
                break;
            case "denied":
                this.Settle("The phone denied the pairing.");
                break;
            case "cancelled":
                this.Settle("The pairing was cancelled.");
                break;
            case "failed":
                this.Settle(state.Message ?? "The pairing attempt failed.");
                break;
            default:
                // "offer": keep waiting.
                break;
        }
    }

    private void AutoConfirm(PairingPeer? peer)
    {
        if (this.confirmed)
        {
            return;
        }

        this.confirmed = true;

        // The scan is the human's consent; the 256-bit offer secret
        // authenticates the peer. Grant exactly what the peer requested and
        // let the protocol finish without a second manual confirmation.
        try
        {
            NativeRappService.ConfirmPairing(this.handle, []);
        }
        catch (NativeRappException error)
        {
            this.Settle(failure: error.Message);
            return;
        }

        this.StatusText.Text = peer is null ? "Pairing…" : $"Pairing with {peer.DisplayName}…";
        this.QrFrame.Visibility = Visibility.Collapsed;
        this.PairingCodeText.Visibility = Visibility.Collapsed;
    }

    private void Settle(string? failure)
    {
        if (this.settled)
        {
            return;
        }

        this.settled = true;
        this.Failure = failure;
        this.timer.Stop();
        this.Hide();
    }

    private void OnClosing(ContentDialog sender, ContentDialogClosingEventArgs args)
    {
        this.timer.Stop();
        if (this.PairedHandle is null)
        {
            // Cancel button or dismissal without a completed pairing: drop the offer.
            try
            {
                NativeRappService.CancelPairing(this.handle);
            }
            catch (NativeRappException ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"CancelPairing ignored on dismissal: {ex.Message}"
                );
            }

            NativeRappService.EndPairing(this.handle);
        }
    }
}
