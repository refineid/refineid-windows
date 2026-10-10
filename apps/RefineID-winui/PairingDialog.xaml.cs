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

using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

/// <summary>
/// Takes the code the phone shows, starts the pairing, polls its progress,
/// hosts the on-screen confirmation, and reports the paired handle or the
/// failure.
/// </summary>
internal sealed partial class PairingDialog : ContentDialog
{
    private readonly string requesterName;
    private readonly DispatcherQueueTimer timer;
    private ulong? handle;
    private bool confirmed;
    private bool settled;

    /// <summary>The handle once the pairing completed, otherwise null.</summary>
    public ulong? PairedHandle { get; private set; }

    /// <summary>A human-readable failure, set when pairing did not complete.</summary>
    public string? Failure { get; private set; }

    public PairingDialog(string requesterName, DispatcherQueue dispatcher, TimeSpan pollInterval)
    {
        this.InitializeComponent();
        this.requesterName = requesterName;

        this.timer = dispatcher.CreateTimer();
        this.timer.Interval = pollInterval;
        this.timer.Tick += this.OnPoll;

        this.PrimaryButtonClick += this.OnPair;
        this.Closing += this.OnClosing;
    }

    private async void OnPair(ContentDialog sender, ContentDialogButtonClickEventArgs args)
    {
        // The dialog stays open while the pairing runs.
        args.Cancel = true;
        if (this.handle is not null)
        {
            return;
        }

        string code = this.CodeBox.Text;
        this.IsPrimaryButtonEnabled = false;
        this.CodeBox.IsEnabled = false;
        BeginPairingResult begun;
        try
        {
            begun = await Task.Run(() => NativeRappService.BeginPairing(code, this.requesterName))
                .ConfigureAwait(true);
        }
        catch (NativeRappException error)
        {
            this.ShowStatus(error.Message);
            this.IsPrimaryButtonEnabled = true;
            this.CodeBox.IsEnabled = true;
            return;
        }

        this.handle = begun.Handle;
        this.StatusText.Visibility = Visibility.Collapsed;
        this.WaitRing.IsActive = true;
        this.WaitRing.Visibility = Visibility.Visible;
        this.timer.Start();
    }

    private void ShowStatus(string message)
    {
        this.StatusText.Text = message;
        this.StatusText.Visibility = Visibility.Visible;
    }

    private void OnPoll(DispatcherQueueTimer sender, object args)
    {
        if (this.handle is not ulong current)
        {
            return;
        }

        PairingState state;
        try
        {
            state = NativeRappService.PollPairing(current);
        }
        catch (NativeRappException error)
        {
            this.Settle(failure: error.Message);
            return;
        }

        switch (state.State)
        {
            case "awaiting_confirmation":
                this.AutoConfirm(current, state.Peer);
                break;
            case "paired":
                this.PairedHandle = current;
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

    private void AutoConfirm(ulong current, PairingPeer? peer)
    {
        if (this.confirmed)
        {
            return;
        }

        this.confirmed = true;

        // Typing the code the phone shows is the human's consent, and CPace
        // over that code authenticates the peer. Grant exactly what the peer
        // requested and let the protocol finish without a second manual
        // confirmation.
        try
        {
            NativeRappService.ConfirmPairing(current, []);
        }
        catch (NativeRappException error)
        {
            this.Settle(failure: error.Message);
            return;
        }

        if (peer is not null)
        {
            this.ShowStatus(peer.DisplayName);
        }
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
        if (args.Result == ContentDialogResult.Primary && !this.settled)
        {
            return;
        }

        this.timer.Stop();
        if (this.PairedHandle is null && this.handle is ulong current)
        {
            // Cancel button or dismissal without a completed pairing: stop the attempt.
            try
            {
                NativeRappService.CancelPairing(current);
            }
            catch (NativeRappException ex)
            {
                System.Diagnostics.Debug.WriteLine(
                    $"CancelPairing ignored on dismissal: {ex.Message}"
                );
            }

            NativeRappService.EndPairing(current);
        }
    }
}
