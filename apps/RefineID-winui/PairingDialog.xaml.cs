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
using Microsoft.UI.Xaml.Media;

/// <summary>
/// Takes the code the phone shows, as the phone shows it: three groups of
/// two, and a complete code starts the pairing at once. The dialog polls
/// the pairing's progress, hosts the on-screen confirmation, and reports
/// the paired handle. A pairing that does not complete says why under the
/// code and takes the next one.
/// </summary>
internal sealed partial class PairingDialog : ContentDialog
{
    /// <summary>
    /// A pairing code is six Crockford Base32 symbols, shown in groups of
    /// two (RAPP v26.10.29 section 3.1). The alphabet leaves out I, L, O
    /// and U.
    /// </summary>
    private const int CodeLength = 6;
    private const int GroupSize = 2;
    private const string Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /// <summary>
    /// What an empty group shows: two blanks the width of its symbols, so
    /// nothing reads as a code before one is typed.
    /// </summary>
    private const string EmptyGroup = "\u00A0\u00A0";

    private readonly DispatcherQueueTimer timer;
    private ulong? handle;
    private bool confirmed;
    private bool settled;

    /// <summary>The handle once the pairing completed, otherwise null.</summary>
    public ulong? PairedHandle { get; private set; }

    public PairingDialog(DispatcherQueue dispatcher, TimeSpan pollInterval)
    {
        this.InitializeComponent();

        this.timer = dispatcher.CreateTimer();
        this.timer.Interval = pollInterval;
        this.timer.Tick += this.OnPoll;

        this.Opened += (sender, args) => this.FocusCode();
        this.Closing += this.OnClosing;
        this.Render(string.Empty);
    }

    private TextBlock[] Groups => [this.Group0, this.Group1, this.Group2];

    private Border[] GroupLines => [this.Group0Line, this.Group1Line, this.Group2Line];

    /// <summary>
    /// Keeps the box to the code's own symbols: separators and anything
    /// outside the alphabet fall away as typed or pasted, letters turn
    /// upper case, and the sixth symbol starts the pairing.
    /// </summary>
    private async void CodeBox_TextChanged(object sender, TextChangedEventArgs args)
    {
        if (this.handle is not null)
        {
            return;
        }

        string typed = this.CodeBox.Text;
        string code = Normalize(typed);
        if (!string.Equals(code, typed, StringComparison.Ordinal))
        {
            // Setting the text raises this event again with the clean code.
            this.CodeBox.Text = code;
            this.CodeBox.SelectionStart = code.Length;
            return;
        }

        this.Render(code);
        if (code.Length == CodeLength)
        {
            await this.BeginAsync(code).ConfigureAwait(true);
        }
    }

    /// <summary>The code's symbols in `typed`, upper case, at most a code's worth.</summary>
    private static string Normalize(string typed)
    {
        var code = new System.Text.StringBuilder(CodeLength);
        foreach (char symbol in typed)
        {
            char upper = char.ToUpperInvariant(symbol);
            if (Alphabet.Contains(upper, StringComparison.Ordinal))
            {
                code.Append(upper);
                if (code.Length == CodeLength)
                {
                    break;
                }
            }
        }

        return code.ToString();
    }

    /// <summary>
    /// Shows `code` in its groups: a typed group in the text colour, an
    /// empty one blank, and the accent line under the group being typed.
    /// </summary>
    private void Render(string code)
    {
        int current = code.Length / GroupSize;
        TextBlock[] groups = this.Groups;
        Border[] lines = this.GroupLines;
        for (int index = 0; index < groups.Length; index++)
        {
            int start = Math.Min(index * GroupSize, code.Length);
            string digits = code.Substring(start, Math.Min(GroupSize, code.Length - start));
            bool typedGroup = digits.Length > 0;
            groups[index].Text = typedGroup ? digits : EmptyGroup;
            groups[index].Foreground = Brush(
                typedGroup ? "TextFillColorPrimaryBrush" : "TextFillColorSecondaryBrush"
            );
            bool typing = index == current && code.Length < CodeLength;
            lines[index].BorderBrush = Brush(
                typing ? "AccentFillColorDefaultBrush" : "ControlStrokeColorDefaultBrush"
            );
        }
    }

    /// <summary>A theme brush by name; a theme without it leaves the element's own.</summary>
    private static Brush? Brush(string key) =>
        Application.Current.Resources.TryGetValue(key, out object? resource)
        && resource is Brush brush
            ? brush
            : null;

    private void FocusCode() => _ = this.CodeBox.Focus(FocusState.Programmatic);

    /// <summary>Starts the pairing with `code`; the dialog stays open while it runs.</summary>
    private async Task BeginAsync(string code)
    {
        this.CodeBox.IsEnabled = false;
        this.StatusText.Visibility = Visibility.Collapsed;
        BeginPairingResult begun;
        try
        {
            begun = await Task.Run(() => NativeRappService.BeginPairing(code)).ConfigureAwait(true);
        }
        catch (NativeRappException error)
        {
            this.TakeNextCode(error.Message);
            return;
        }

        this.handle = begun.Handle;
        this.WaitRing.IsActive = true;
        this.WaitRing.Visibility = Visibility.Visible;
        this.timer.Start();
    }

    /// <summary>
    /// A pairing that did not complete: says why under the code, lets go
    /// of the attempt, and takes the next code, as the Apple app does.
    /// </summary>
    private void TakeNextCode(string reason)
    {
        this.timer.Stop();
        this.WaitRing.IsActive = false;
        this.WaitRing.Visibility = Visibility.Collapsed;
        if (this.handle is ulong current)
        {
            NativeRappService.EndPairing(current);
        }

        this.handle = null;
        this.confirmed = false;
        this.ShowStatus(reason);
        this.CodeBox.IsEnabled = true;
        this.CodeBox.Text = string.Empty;
        this.Render(string.Empty);
        this.FocusCode();
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
            this.TakeNextCode(error.Message);
            return;
        }

        switch (state.State)
        {
            case "awaiting_confirmation":
                this.AutoConfirm(current, state.Peer);
                break;
            case "paired":
                this.PairedHandle = current;
                this.Settle();
                break;
            case "denied":
                this.TakeNextCode(Strings.Get("PairingDenied"));
                break;
            case "cancelled":
                this.TakeNextCode(Strings.Get("PairingCancelled"));
                break;
            case "failed":
                this.TakeNextCode(state.Message ?? Strings.Get("PairingFailed"));
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
            this.TakeNextCode(error.Message);
            return;
        }

        if (peer is not null)
        {
            this.ShowStatus(peer.DisplayName);
        }
    }

    /// <summary>The pairing completed; the dialog closes with its handle.</summary>
    private void Settle()
    {
        if (this.settled)
        {
            return;
        }

        this.settled = true;
        this.timer.Stop();
        this.Hide();
    }

    private void OnClosing(ContentDialog sender, ContentDialogClosingEventArgs args)
    {
        this.timer.Stop();
        if (this.PairedHandle is null && this.handle is ulong current)
        {
            // Cancel button or dismissal without a completed pairing: stop the attempt.
            try
            {
                NativeRappService.CancelPairing(current);
            }
            catch (NativeRappException)
            {
                // The requester bridge reports its own failure; the dismissal
                // goes on.
            }

            NativeRappService.EndPairing(current);
        }
    }
}
