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
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;

/// <summary>
/// A settings card a holder can act on with a pointer, the keyboard or UI
/// Automation. The toolkit card's automation peer offers no Invoke pattern, so
/// assistive technology could see this control but not activate it, and
/// WinUI gives no way to raise a button's Click from code: every path reports
/// through <see cref="Activated"/>.
/// </summary>
[SuppressMessage(
    "Performance",
    "CA1812:Avoid uninstantiated internal classes",
    Justification = "Instantiated through XAML type activation."
)]
internal sealed partial class ActionCard : SettingsCard
{
    public ActionCard()
    {
        this.Click += (sender, args) => this.Activated?.Invoke(this, args);
    }

    /// <summary>The holder acted on the card.</summary>
    public event RoutedEventHandler? Activated;

    protected override AutomationPeer OnCreateAutomationPeer() => new Peer(this);

    /// <summary>The card as UI Automation sees it: a button.</summary>
    private sealed partial class Peer(ActionCard owner)
        : FrameworkElementAutomationPeer(owner),
            IInvokeProvider
    {
        public void Invoke()
        {
            if (!owner.IsEnabled || !owner.IsClickEnabled)
            {
                throw new ElementNotEnabledException();
            }
            owner.Activated?.Invoke(owner, new RoutedEventArgs());
        }

        protected override object? GetPatternCore(PatternInterface patternInterface) =>
            patternInterface == PatternInterface.Invoke && owner.IsClickEnabled
                ? this
                : base.GetPatternCore(patternInterface);

        protected override AutomationControlType GetAutomationControlTypeCore() =>
            owner.IsClickEnabled ? AutomationControlType.Button : AutomationControlType.Group;

        protected override string GetClassNameCore() => nameof(ActionCard);
    }
}
