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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

/// <summary>
/// Safe managed bridge to refineid_settings_ffi for local card detection and inspection.
/// </summary>
internal static partial class LocalCardService
{
    private const string Library = "refineid_settings_ffi";

    [LibraryImport(Library, EntryPoint = "refineid_settings_present_readers")]
    private static partial nint PresentReadersNative();

    [LibraryImport(Library, EntryPoint = "refineid_settings_inspect")]
    private static partial nint InspectNative([In] byte[] reader, nuint readerLength);

    [LibraryImport(Library, EntryPoint = "refineid_settings_string_free")]
    private static partial void StringFree(nint value);

    internal static IReadOnlyList<string> PresentReaders()
    {
        try
        {
            return Invoke(
                PresentReadersNative,
                LocalCardJsonContext.Default.NativeEnvelopeReaderList
            ).Readers;
        }
        catch (NativeRappException ex)
        {
            Debug.WriteLine($"PresentReaders native error: {ex.Message}");
            return [];
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"PresentReaders JSON parse error: {ex.Message}");
            return [];
        }
    }

    /// <summary>Inspects a connected smart card in the given reader.</summary>
    internal static LocalCardSnapshot? Inspect(string reader)
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        try
        {
            return Invoke(
                () => InspectNative(readerBytes, (nuint)readerBytes.Length),
                LocalCardJsonContext.Default.NativeEnvelopeLocalCardSnapshot
            );
        }
        catch (NativeRappException ex)
        {
            Debug.WriteLine($"Inspect native error: {ex.Message}");
            return null;
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"Inspect JSON parse error: {ex.Message}");
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readerBytes);
        }
    }

    private static T Invoke<T>(Func<nint> operation, JsonTypeInfo<NativeEnvelope<T>> envelopeInfo)
    {
        nint response = operation();
        if (response == nint.Zero)
        {
            throw new NativeRappException(
                "native_allocation_failed",
                "The card service did not respond."
            );
        }

        try
        {
            string json =
                Marshal.PtrToStringUTF8(response)
                ?? throw new NativeRappException(
                    "native_response_invalid",
                    "The card service response was not valid UTF-8."
                );
            NativeEnvelope<T> envelope =
                JsonSerializer.Deserialize(json, envelopeInfo)
                ?? throw new NativeRappException(
                    "native_response_invalid",
                    "The card service response was not valid JSON."
                );
            if (!envelope.Ok)
            {
                throw new NativeRappException(
                    envelope.Error?.Code ?? "native_error",
                    envelope.Error?.Message ?? "The card service failed."
                );
            }

            return envelope.Data
                ?? throw new NativeRappException(
                    "native_response_empty",
                    "The card service response carried no data."
                );
        }
        finally
        {
            StringFree(response);
        }
    }
}
