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

using System.Text.RegularExpressions;
using Xunit;

/// <summary>
/// Every language carries the same texts, and the markup and the code name
/// only texts that exist. A missing text shows its key to the holder.
/// </summary>
public sealed partial class ResourceTests
{
    /// <summary>The language every other is compared with.</summary>
    private const string ReferenceLanguage = "en-US";

    [GeneratedRegex(@"x:Uid=""([^""]+)""")]
    private static partial Regex Uid();

    [GeneratedRegex(@"Strings\.(?:Get|Format)\(\s*""([^""]+)""")]
    private static partial Regex CodeKey();

    [GeneratedRegex(@"\{(\d+)[^}]*\}")]
    private static partial Regex Placeholder();

    /// <summary>PIN 1 and PIN 2 are written with the space (DVV's terms).</summary>
    [GeneratedRegex(@"\b(?:PIN|PUK)\d", RegexOptions.IgnoreCase)]
    private static partial Regex UnspacedPinName();

    public static TheoryData<string> OtherLanguages()
    {
        TheoryData<string> languages = [];
        foreach (string language in Repository.Languages)
        {
            if (language != ReferenceLanguage)
            {
                languages.Add(language);
            }
        }
        return languages;
    }

    public static TheoryData<string> AllLanguages()
    {
        TheoryData<string> languages = [];
        foreach (string language in Repository.Languages)
        {
            languages.Add(language);
        }
        return languages;
    }

    [Theory]
    [MemberData(nameof(OtherLanguages))]
    public void A_language_has_exactly_the_reference_languages_texts(string language)
    {
        var reference = Repository.Resources(ReferenceLanguage).Keys.ToHashSet();
        var translated = Repository.Resources(language).Keys.ToHashSet();
        Assert.Empty(reference.Except(translated));
        Assert.Empty(translated.Except(reference));
    }

    [Theory]
    [MemberData(nameof(AllLanguages))]
    public void No_text_is_empty(string language)
    {
        Assert.Empty(
            Repository
                .Resources(language)
                .Where(text => string.IsNullOrWhiteSpace(text.Value))
                .Select(text => text.Key)
        );
    }

    [Theory]
    [MemberData(nameof(OtherLanguages))]
    public void A_translation_fills_the_same_placeholders(string language)
    {
        Dictionary<string, string> reference = Repository.Resources(ReferenceLanguage);
        Dictionary<string, string> translated = Repository.Resources(language);
        Assert.Empty(
            reference
                .Where(text =>
                    translated.TryGetValue(text.Key, out string? other)
                    && !Placeholders(text.Value).SetEquals(Placeholders(other))
                )
                .Select(text => text.Key)
        );
    }

    [Theory]
    [MemberData(nameof(AllLanguages))]
    public void A_pin_is_named_with_the_space(string language)
    {
        Assert.Empty(
            Repository
                .Resources(language)
                .Where(text => UnspacedPinName().IsMatch(text.Value))
                .Select(text => text.Key)
        );
    }

    [Fact]
    public void Every_uid_in_the_markup_has_a_text()
    {
        var keys = Repository.Resources(ReferenceLanguage).Keys;
        Assert.Empty(
            Repository
                .Captures(Repository.Xaml, Uid())
                .Distinct(StringComparer.Ordinal)
                .Where(uid => !keys.Any(key => key.StartsWith(uid + ".", StringComparison.Ordinal)))
                .ToList()
        );
    }

    [Fact]
    public void Every_key_the_code_names_has_a_text()
    {
        var keys = Repository.Resources(ReferenceLanguage).Keys.ToHashSet();
        Assert.Empty(
            Repository
                .Captures(Repository.CSharp, CodeKey())
                .Distinct(StringComparer.Ordinal)
                .Where(key => !keys.Contains(key))
                .ToList()
        );
    }

    private static HashSet<string> Placeholders(string text) =>
        Placeholder().Matches(text).Select(match => match.Groups[1].Value).ToHashSet();
}
