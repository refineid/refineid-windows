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
/// The app and the Rust bridges agree on the entry points. A name that does
/// not match compiles on both sides and fails only when the holder reaches
/// that call.
/// </summary>
public sealed partial class FfiTests
{
    [GeneratedRegex(@"private const string Library = ""([^""]+)""")]
    private static partial Regex LibraryName();

    [GeneratedRegex(@"LibraryImport\(\s*Library\s*,\s*EntryPoint\s*=\s*""([^""]+)""")]
    private static partial Regex ImportedEntryPoint();

    [GeneratedRegex(@"LibraryImport\(\s*Library\b")]
    private static partial Regex Import();

    [GeneratedRegex(
        @"#\[unsafe\(no_mangle\)\]\s*(?:#\[[^\]]*\]\s*)*pub\s+(?:unsafe\s+)?extern\s+""C""\s+fn\s+(\w+)"
    )]
    private static partial Regex ExportedFunction();

    public static TheoryData<string> ImportingFiles()
    {
        TheoryData<string> files = [];
        foreach (string file in Repository.CSharp)
        {
            if (LibraryName().IsMatch(File.ReadAllText(file)))
            {
                files.Add(Path.GetRelativePath(Repository.App, file));
            }
        }
        return files;
    }

    [Fact]
    public void The_app_imports_from_the_bridges() => Assert.NotEmpty(ImportingFiles());

    [Theory]
    [MemberData(nameof(ImportingFiles))]
    public void Every_import_is_exported_by_its_bridge(string fileName)
    {
        string source = File.ReadAllText(Path.Combine(Repository.App, fileName));
        string crate = LibraryName().Match(source).Groups[1].Value.Replace('_', '-');
        var bridge = Directory.EnumerateFiles(
            Path.Combine(Repository.Crates, crate, "src"),
            "*.rs",
            SearchOption.AllDirectories
        );
        var exports = Repository.Captures(bridge, ExportedFunction()).ToHashSet();
        var imports = ImportedEntryPoint().Matches(source).Select(match => match.Groups[1].Value);

        Assert.NotEmpty(exports);
        // An import written another way would otherwise go unchecked.
        Assert.Equal(Import().Count(source), imports.Count());
        Assert.Empty(imports.Where(entryPoint => !exports.Contains(entryPoint)).ToList());
    }
}
