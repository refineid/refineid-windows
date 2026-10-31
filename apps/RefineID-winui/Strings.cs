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

using System.Globalization;
using Microsoft.Windows.ApplicationModel.Resources;

/// <summary>
/// The texts the code shows to the user, read from
/// Strings/&lt;language&gt;/Resources.resw for the Windows display language;
/// a language without a text falls back to English. The texts the XAML
/// shows come from the same files through x:Uid.
/// </summary>
internal static class Strings
{
    private static readonly ResourceLoader Loader = new();

    /// <summary>The text under <paramref name="key"/>.</summary>
    public static string Get(string key) => Loader.GetString(key);

    /// <summary>
    /// The text under <paramref name="key"/> with its numbered placeholders
    /// filled in the user's culture.
    /// </summary>
    public static string Format(string key, params object[] arguments) =>
        string.Format(CultureInfo.CurrentCulture, Loader.GetString(key), arguments);
}
