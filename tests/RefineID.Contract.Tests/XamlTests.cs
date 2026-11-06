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

namespace RefineID.Contract.Tests;

using System.Xml;
using System.Xml.Linq;
using Xunit;

/// <summary>
/// The markup rules a XAML compile does not enforce, which UI Automation
/// clients and assistive technology rely on
/// (doc/accessibility-and-ui-automation.md).
/// </summary>
public sealed class XamlTests
{
    private const string AutomationId = "AutomationProperties.AutomationId";
    private const string ClickEnabled = "IsClickEnabled";
    private const string SettingsCard = "SettingsCard";

    /// <summary>The controls a holder acts on, by element name.</summary>
    private static readonly string[] ActionableControls =
    [
        "Button",
        "CheckBox",
        "ComboBox",
        "HyperlinkButton",
        "PasswordBox",
        "RadioButton",
        "TextBox",
        "ToggleSwitch",
    ];

    public static TheoryData<string> Pages()
    {
        TheoryData<string> pages = [];
        foreach (string page in Repository.Xaml)
        {
            pages.Add(Path.GetRelativePath(Repository.App, page));
        }
        return pages;
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void An_automation_id_is_unique_on_its_page(string page)
    {
        Assert.Empty(
            Elements(page)
                .Select(element => element.Attribute(AutomationId)?.Value)
                .OfType<string>()
                .GroupBy(id => id, StringComparer.Ordinal)
                .Where(group => group.Skip(1).Any())
                .Select(group => group.Key)
        );
    }

    [Theory]
    [MemberData(nameof(Pages))]
    public void An_actionable_control_has_an_automation_id(string page)
    {
        Assert.Empty(
            Elements(page)
                .Where(element =>
                    ActionableControls.Contains(element.Name.LocalName)
                    && element.Attribute(AutomationId) is null
                )
                .Select(Describe)
        );
    }

    /// <summary>The toolkit card offers UI Automation no way to activate it.</summary>
    [Theory]
    [MemberData(nameof(Pages))]
    public void A_clickable_card_is_an_action_card(string page)
    {
        Assert.Empty(
            Elements(page)
                .Where(element =>
                    element.Name.LocalName == SettingsCard
                    && element.Attribute(ClickEnabled) is not null
                )
                .Select(Describe)
        );
    }

    private static IEnumerable<XElement> Elements(string page) =>
        XDocument.Load(Path.Combine(Repository.App, page), LoadOptions.SetLineInfo).Descendants();

    private static string Describe(XElement element) =>
        $"{element.Name.LocalName} at line {((IXmlLineInfo)element).LineNumber}";
}
