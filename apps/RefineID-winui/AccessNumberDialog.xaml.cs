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

using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

/// <summary>
/// Takes the six-digit access number printed on a card that sits on a
/// contactless reader, proves it on the card and stores it, so the card
/// reads without asking again. The sixth digit starts the proof; a number
/// the card refuses says so under the digits and takes the next one.
/// </summary>
internal sealed partial class AccessNumberDialog : ContentDialog
{
    /// <summary>The number is six digits, shown in two groups of three.</summary>
    private const int NumberLength = 6;
    private const int GroupSize = 3;

    /// <summary>Three blanks the width of a group's digits.</summary>
    private const string EmptyGroup = "   ";

    private readonly string reader;
    private bool proving;

    /// <summary>Whether the number was proved and stored.</summary>
    public bool Primed { get; private set; }

    public AccessNumberDialog(string reader)
    {
        this.InitializeComponent();
        this.reader = reader;
        this.Opened += (sender, args) => this.FocusNumber();
        this.Render(string.Empty);
    }

    private TextBlock[] Groups => [this.Group0, this.Group1];

    private Border[] GroupLines => [this.Group0Line, this.Group1Line];

    /// <summary>
    /// Keeps the box to digits: anything else falls away as typed or
    /// pasted, and the sixth digit proves the number on the card.
    /// </summary>
    private async void NumberBox_TextChanged(object sender, TextChangedEventArgs args)
    {
        if (this.proving)
        {
            return;
        }

        string typed = this.NumberBox.Text;
        string digits = Normalize(typed);
        if (!string.Equals(digits, typed, StringComparison.Ordinal))
        {
            // Setting the text raises this event again with the clean digits.
            this.NumberBox.Text = digits;
            this.NumberBox.SelectionStart = digits.Length;
            return;
        }

        this.Render(digits);
        if (digits.Length == NumberLength)
        {
            await this.ProveAsync(digits).ConfigureAwait(true);
        }
    }

    /// <summary>The digits in `typed`, at most a number's worth.</summary>
    private static string Normalize(string typed)
    {
        var digits = new System.Text.StringBuilder(NumberLength);
        foreach (char symbol in typed)
        {
            if (char.IsAsciiDigit(symbol))
            {
                digits.Append(symbol);
                if (digits.Length == NumberLength)
                {
                    break;
                }
            }
        }

        return digits.ToString();
    }

    /// <summary>
    /// Shows `digits` in their groups: a typed group in the text colour,
    /// an empty one blank, and the accent line under the group being typed.
    /// </summary>
    private void Render(string digits)
    {
        int current = digits.Length / GroupSize;
        TextBlock[] groups = this.Groups;
        Border[] lines = this.GroupLines;
        for (int index = 0; index < groups.Length; index++)
        {
            int start = Math.Min(index * GroupSize, digits.Length);
            string part = digits.Substring(start, Math.Min(GroupSize, digits.Length - start));
            bool typedGroup = part.Length > 0;
            groups[index].Text = typedGroup ? part : EmptyGroup;
            groups[index].Foreground = Brush(
                typedGroup ? "TextFillColorPrimaryBrush" : "TextFillColorSecondaryBrush"
            );
            bool typing = index == current && digits.Length < NumberLength;
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

    private void FocusNumber() => _ = this.NumberBox.Focus(FocusState.Programmatic);

    /// <summary>
    /// Proves `digits` on the card over PACE and stores them; the dialog
    /// closes on success and takes the next number on a refusal. The digits
    /// leave this method only as the call's argument.
    /// </summary>
    private async Task ProveAsync(string digits)
    {
        this.proving = true;
        this.NumberBox.IsEnabled = false;
        this.StatusText.Visibility = Visibility.Collapsed;
        this.WaitRing.IsActive = true;
        this.WaitRing.Visibility = Visibility.Visible;
        try
        {
            _ = await Task.Run(() => LocalCardService.PrimeContactless(this.reader, digits))
                .ConfigureAwait(true);
            this.Primed = true;
            this.Hide();
        }
        catch (NativeRappException error)
        {
            this.TakeNextNumber(error.Message);
        }
        finally
        {
            this.WaitRing.IsActive = false;
            this.WaitRing.Visibility = Visibility.Collapsed;
            this.proving = false;
        }
    }

    /// <summary>A refused number: says why under the digits and takes the next one.</summary>
    private void TakeNextNumber(string reason)
    {
        this.StatusText.Text = reason;
        this.StatusText.Visibility = Visibility.Visible;
        this.NumberBox.IsEnabled = true;
        this.NumberBox.Text = string.Empty;
        this.Render(string.Empty);
        this.FocusNumber();
    }
}
