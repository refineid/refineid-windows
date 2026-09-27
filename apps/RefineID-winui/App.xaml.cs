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

using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using Microsoft.UI.Xaml;

/// <summary>The requester application entry point: one window, one page.</summary>
[SuppressMessage(
    "Design",
    "CA1515:Consider making public types internal",
    Justification = "The WinUI XAML generator declares the application class as public."
)]
public partial class App : Application
{
    private Window? window;

    public App()
    {
        this.UnhandledException += (sender, e) =>
        {
            Debug.WriteLine(
                $"Message: {e.Message}\nException: {e.Exception}\nTrace: {e.Exception?.StackTrace}\nInner: {e.Exception?.InnerException}"
            );
        };
        AppDomain.CurrentDomain.UnhandledException += (sender, e) =>
        {
            Debug.WriteLine($"Domain Exception: {e.ExceptionObject}");
        };
        this.InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        try
        {
            this.window = new MainWindow();
            this.window.Activate();
        }
        // codeql[cs/catch-of-all-exceptions]
        catch (Exception ex)
        {
            Debug.WriteLine($"Launch error: {ex}\n{ex.StackTrace}");
            throw;
        }
    }
}
