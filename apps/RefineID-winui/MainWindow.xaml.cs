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

using System;
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Windows.Graphics;
using WinRT.Interop;

/// <summary>The single window: a Mica-backed title bar over the main page.</summary>
internal sealed partial class MainWindow : Window
{
    /// <summary>Default window size, fitting within standard 1024x768 display.</summary>
    private static readonly SizeInt32 InitialSize = new(660, 700);

    /// <summary>
    /// Minimum window size in effective pixels. Keeps every settings card
    /// (Document and Identity sections) fully visible: shrinking further
    /// would clip the trailing actions, which have no horizontal scroll.
    /// </summary>
    private static readonly SizeInt32 MinimumSize = new(560, 600);

    private const uint WindowMessageGetMinMaxInfo = 0x0024;
    private const uint SubclassId = 1;

    private readonly SubclassProc subclassProc;

    [StructLayout(LayoutKind.Sequential)]
    private struct Point2D
    {
        public int X;
        public int Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MinMaxInfo
    {
        public Point2D Reserved;
        public Point2D MaxSize;
        public Point2D MaxPosition;
        public Point2D MinTrackSize;
        public Point2D MaxTrackSize;
    }

    private delegate IntPtr SubclassProc(
        IntPtr hWnd,
        uint uMsg,
        IntPtr wParam,
        IntPtr lParam,
        IntPtr uIdSubclass,
        uint dwRefData
    );

    [DllImport("comctl32.dll", SetLastError = true)]
    private static extern bool SetWindowSubclass(
        IntPtr hWnd,
        SubclassProc pfnSubclass,
        uint uIdSubclass,
        UIntPtr dwRefData
    );

    [DllImport("comctl32.dll")]
    private static extern IntPtr DefSubclassProc(
        IntPtr hWnd,
        uint uMsg,
        IntPtr wParam,
        IntPtr lParam
    );

    [DllImport("user32.dll")]
    private static extern uint GetDpiForWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetDpiForSystem();

    public MainWindow()
    {
        this.InitializeComponent();
        this.ExtendsContentIntoTitleBar = true;
        this.SetTitleBar(this.AppTitleBar);
        this.AppWindow.SetIcon("Assets/AppIcon.ico");
        this.ApplyInitialPlacement();
        this.Activated += this.OnFirstActivated;
        this.subclassProc = new SubclassProc(this.WindowSubclassProc);
        IntPtr hWnd = WindowNative.GetWindowHandle(this);
        if (hWnd != IntPtr.Zero)
        {
            SetWindowSubclass(hWnd, this.subclassProc, SubclassId, UIntPtr.Zero);
        }

        this.RootFrame.Navigate(typeof(MainPage));
    }

    private bool placementApplied;

    private void ApplyInitialPlacement()
    {
        this.AppWindow.Resize(InitialSize);
        this.AppWindow.Move(new PointInt32(50, 20));
    }

    private void OnFirstActivated(object sender, WindowActivatedEventArgs args)
    {
        // Sizing requested before first activation can be dropped, so
        // re-apply once the window is shown. Runs exactly once.
        if (!this.placementApplied)
        {
            this.placementApplied = true;
            this.ApplyInitialPlacement();
        }

        this.Activated -= this.OnFirstActivated;
    }

    private IntPtr WindowSubclassProc(
        IntPtr hWnd,
        uint uMsg,
        IntPtr wParam,
        IntPtr lParam,
        IntPtr uIdSubclass,
        uint dwRefData
    )
    {
        if (uMsg == WindowMessageGetMinMaxInfo && lParam != IntPtr.Zero)
        {
            uint dpi = GetDpiForWindow(hWnd);
            if (dpi == 0)
            {
                dpi = GetDpiForSystem();
            }

            double scale = dpi == 0 ? 1.0 : dpi / 96.0;
            MinMaxInfo info = Marshal.PtrToStructure<MinMaxInfo>(lParam);
            info.MinTrackSize = new Point2D
            {
                X = (int)Math.Ceiling(MinimumSize.Width * scale),
                Y = (int)Math.Ceiling(MinimumSize.Height * scale),
            };
            Marshal.StructureToPtr(info, lParam, false);
        }

        return DefSubclassProc(hWnd, uMsg, wParam, lParam);
    }
}
