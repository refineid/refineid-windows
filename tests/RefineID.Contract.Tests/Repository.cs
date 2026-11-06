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
using System.Xml.Linq;

/// <summary>The checked-in files the contract tests read.</summary>
internal static class Repository
{
    /// <summary>The file that marks the repository root.</summary>
    private const string RootMarker = "AGENTS.md";

    /// <summary>The repository root, found upward from the test binary.</summary>
    internal static readonly string Root = FindRoot();

    /// <summary>The WinUI app's source directory.</summary>
    internal static readonly string App = Path.Combine(Root, "apps", "RefineID-winui");

    /// <summary>The Rust crates.</summary>
    internal static readonly string Crates = Path.Combine(Root, "crates");

    /// <summary>The app's markup files.</summary>
    internal static IEnumerable<string> Xaml => Source("*.xaml");

    /// <summary>The app's C# files.</summary>
    internal static IEnumerable<string> CSharp => Source("*.cs");

    /// <summary>The app's languages, as <c>Strings</c> directory names.</summary>
    internal static IEnumerable<string> Languages =>
        Directory.EnumerateDirectories(Path.Combine(App, "Strings")).Select(Path.GetFileName)!;

    /// <summary>One language's texts by resource name.</summary>
    internal static Dictionary<string, string> Resources(string language)
    {
        XDocument file = XDocument.Load(Path.Combine(App, "Strings", language, "Resources.resw"));
        return file.Root!.Elements("data")
            .ToDictionary(
                entry => entry.Attribute("name")!.Value,
                entry => entry.Element("value")?.Value ?? "",
                StringComparer.Ordinal
            );
    }

    /// <summary>Every capture of the pattern's first group across the files.</summary>
    internal static IEnumerable<string> Captures(IEnumerable<string> files, Regex pattern) =>
        files.SelectMany(file =>
            pattern.Matches(File.ReadAllText(file)).Select(match => match.Groups[1].Value)
        );

    /// <summary>The app's own files of a kind, without the build's.</summary>
    private static IEnumerable<string> Source(string pattern) =>
        Directory
            .EnumerateFiles(App, pattern, SearchOption.AllDirectories)
            .Where(file =>
            {
                string[] parts = Path.GetRelativePath(App, file).Split(Path.DirectorySeparatorChar);
                return !parts.Contains("bin") && !parts.Contains("obj");
            });

    private static string FindRoot()
    {
        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, RootMarker)))
        {
            directory = directory.Parent;
        }
        return directory?.FullName
            ?? throw new InvalidOperationException("The repository root was not found.");
    }
}
