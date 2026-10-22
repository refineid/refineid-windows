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

#if DEBUG
namespace RefineID;

using System.Globalization;
using System.Runtime.InteropServices;

/// <summary>
/// The app's own failures in a development build, written to the Windows
/// Event Log as every RefineID component writes them (the Rust crate
/// <c>refineid-dev-errors</c>): the Application log, source
/// <see cref="Source"/>, at the error level, with three strings, the event
/// and its cause, the program, and how many times the failure came.
/// </summary>
/// <remarks>
/// A cause is a name and nothing else: an exception by its type, a native
/// failure by its code. Never a PIN, CAN or PUK, their length or digits, a
/// name, certificate content, a serial number, a device name or a pairing
/// identifier. A failure that repeats itself is counted and written again at
/// most once per <see cref="RepeatWindow"/>. Release builds compile none of
/// this.
/// </remarks>
internal static partial class DevErrorLog
{
    /// <summary>The event source every RefineID process writes as.</summary>
    internal const string Source = "RefineID";

    /// <summary>The event identifier of the app's own entries.</summary>
    internal const int AppEventId = 1;

    /// <summary>How long a failure that repeats itself is only counted.</summary>
    internal static readonly TimeSpan RepeatWindow = TimeSpan.FromMinutes(1);

    /// <summary>The longest entry message kept, in characters.</summary>
    private const int MaximumMessageCharacters = 240;

    /// <summary><c>EVENTLOG_ERROR_TYPE</c> (winnt.h).</summary>
    private const ushort ErrorType = 1;

    /// <summary>The category of every entry: none.</summary>
    private const ushort NoCategory = 0;

    /// <summary>The size of the raw data every entry carries: none.</summary>
    private const uint NoRawData = 0;

    private static readonly Lock Gate = new();
    private static readonly string Program = Path.GetFileName(Environment.ProcessPath ?? "");
    private static nint sourceHandle;
    private static string? lastMessage;
    private static DateTimeOffset lastWritten;
    private static int unwritten;

    [LibraryImport(
        "advapi32.dll",
        EntryPoint = "RegisterEventSourceW",
        StringMarshalling = StringMarshalling.Utf16
    )]
    private static partial nint RegisterEventSource(string? serverName, string sourceName);

    [LibraryImport("advapi32.dll", EntryPoint = "ReportEventW")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool ReportEvent(
        nint eventLog,
        ushort type,
        ushort category,
        uint eventId,
        nint userSid,
        ushort stringCount,
        uint dataSize,
        [In] nint[] strings,
        nint rawData
    );

    /// <summary>Records a failure named by the exception's type.</summary>
    internal static void Report(string eventName, Exception error) =>
        Report(eventName, error.GetType().Name);

    /// <summary>
    /// Records one failure: <c>eventName: cause</c>. Never throws: a report
    /// that could break the path it watches would be taken out of it.
    /// </summary>
    internal static void Report(string eventName, string cause)
    {
        string message = Bounded($"{eventName}: {cause}");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        lock (Gate)
        {
            if (string.Equals(message, lastMessage, StringComparison.Ordinal))
            {
                unwritten++;
                if (now - lastWritten < RepeatWindow)
                {
                    return;
                }

                Write(message, unwritten);
                unwritten = 0;
                lastWritten = now;
                return;
            }

            if (lastMessage is not null && unwritten > 0)
            {
                Write(lastMessage, unwritten);
            }

            Write(message, 1);
            lastMessage = message;
            lastWritten = now;
            unwritten = 0;
        }
    }

    /// <summary><paramref name="message"/> on one line, at most <see cref="MaximumMessageCharacters"/> long.</summary>
    private static string Bounded(string message)
    {
        string line = string.Concat(message.Select(c => char.IsControl(c) ? ' ' : c));
        return line.Length <= MaximumMessageCharacters ? line : line[..MaximumMessageCharacters];
    }

    /// <summary>Writes one error event: the message, the program and the occurrences.</summary>
    private static void Write(string message, int occurrences)
    {
        if (sourceHandle == nint.Zero)
        {
            sourceHandle = RegisterEventSource(null, Source);
            if (sourceHandle == nint.Zero)
            {
                return;
            }
        }

        string[] texts = [message, Program, occurrences.ToString(CultureInfo.InvariantCulture)];
        nint[] strings = new nint[texts.Length];
        try
        {
            for (int index = 0; index < texts.Length; index++)
            {
                strings[index] = Marshal.StringToHGlobalUni(texts[index]);
            }

            _ = ReportEvent(
                sourceHandle,
                ErrorType,
                NoCategory,
                AppEventId,
                nint.Zero,
                (ushort)strings.Length,
                NoRawData,
                strings,
                nint.Zero
            );
        }
        finally
        {
            foreach (nint text in strings)
            {
                Marshal.FreeHGlobal(text);
            }
        }
    }
}
#endif
