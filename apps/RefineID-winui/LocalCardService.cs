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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

/// <summary>
/// Safe managed bridge to refineid_settings_ffi: local card detection and
/// inspection for the main screen, and the PIN, recovery, activation, and
/// contactless operations of the card settings screen. Secrets cross the
/// boundary as bounded byte arrays that are zeroed after the call.
/// </summary>
internal static partial class LocalCardService
{
    private const string Library = "refineid_settings_ffi";

    [LibraryImport(Library, EntryPoint = "refineid_settings_present_readers")]
    private static partial nint PresentReadersNative();

    [LibraryImport(Library, EntryPoint = "refineid_settings_detect_local_card_support")]
    private static partial nint DetectLocalCardSupportNative();

    [LibraryImport(Library, EntryPoint = "refineid_settings_inspect")]
    private static partial nint InspectNative([In] byte[] reader, nuint readerLength);

    [LibraryImport(Library, EntryPoint = "refineid_settings_prime_contactless")]
    private static partial nint PrimeContactlessNative(
        [In] byte[] reader,
        nuint readerLength,
        [In] byte[] can,
        nuint canLength
    );

    [LibraryImport(Library, EntryPoint = "refineid_settings_change_pin")]
    private static partial nint ChangePinNative(
        [In] byte[] reader,
        nuint readerLength,
        [In] byte[] serial,
        nuint serialLength,
        byte slot,
        [In] byte[] currentPin,
        nuint currentPinLength,
        [In] byte[] newPin,
        nuint newPinLength,
        [In] byte[] confirmation,
        nuint confirmationLength
    );

    [LibraryImport(Library, EntryPoint = "refineid_settings_unblock_pin")]
    private static partial nint UnblockPinNative(
        [In] byte[] reader,
        nuint readerLength,
        [In] byte[] serial,
        nuint serialLength,
        byte slot,
        [In] byte[] puk,
        nuint pukLength,
        [In] byte[] newPin,
        nuint newPinLength,
        [In] byte[] confirmation,
        nuint confirmationLength
    );

    [LibraryImport(Library, EntryPoint = "refineid_settings_activate")]
    private static partial nint ActivateNative(
        [In] byte[] reader,
        nuint readerLength,
        [In] byte[] serial,
        nuint serialLength,
        [In] byte[] activationCode,
        nuint activationCodeLength,
        [In] byte[] newPin1,
        nuint newPin1Length,
        [In] byte[] pin1Confirmation,
        nuint pin1ConfirmationLength,
        [In] byte[] newPin2,
        nuint newPin2Length,
        [In] byte[] pin2Confirmation,
        nuint pin2ConfirmationLength,
        byte allowReactivate
    );

    [LibraryImport(Library, EntryPoint = "refineid_settings_string_free")]
    private static partial void StringFree(nint value);

    /// <summary>Lists the readers that currently hold a card; empty on failure.</summary>
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

    internal static LocalCardSupport DetectLocalCardSupport()
    {
        try
        {
            return Invoke(
                DetectLocalCardSupportNative,
                LocalCardJsonContext.Default.NativeEnvelopeLocalCardSupport
            );
        }
        catch (NativeRappException ex)
        {
            Debug.WriteLine($"DetectLocalCardSupport native error: {ex.Message}");
            return new LocalCardSupport { State = "unknown" };
        }
        catch (JsonException ex)
        {
            Debug.WriteLine($"DetectLocalCardSupport JSON parse error: {ex.Message}");
            return new LocalCardSupport { State = "unknown" };
        }
    }

    /// <summary>Inspects the card in the given reader.</summary>
    /// <exception cref="NativeRappException">The card service refused or failed.</exception>
    /// <exception cref="JsonException">The card service reply was malformed.</exception>
    internal static LocalCardSnapshot Inspect(string reader)
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        try
        {
            return Invoke(
                () => InspectNative(readerBytes, (nuint)readerBytes.Length),
                LocalCardJsonContext.Default.NativeEnvelopeLocalCardSnapshot
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readerBytes);
        }
    }

    /// <summary>Proves the printed CAN over PACE and saves it for contactless use.</summary>
    internal static ContactlessSnapshot PrimeContactless(string reader, string can)
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        byte[] canBytes = Encoding.ASCII.GetBytes(can);
        try
        {
            return Invoke(
                () =>
                    PrimeContactlessNative(
                        readerBytes,
                        (nuint)readerBytes.Length,
                        canBytes,
                        (nuint)canBytes.Length
                    ),
                LocalCardJsonContext.Default.NativeEnvelopeContactlessSnapshot
            );
        }
        finally
        {
            Zero(readerBytes, canBytes);
        }
    }

    internal static MutationResult ChangePin(
        string reader,
        string serial,
        PinSlot slot,
        string currentPin,
        string newPin,
        string confirmation
    )
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        byte[] serialBytes = Encoding.UTF8.GetBytes(serial);
        byte[] currentBytes = Encoding.ASCII.GetBytes(currentPin);
        byte[] newBytes = Encoding.ASCII.GetBytes(newPin);
        byte[] confirmationBytes = Encoding.ASCII.GetBytes(confirmation);
        try
        {
            return Invoke(
                () =>
                    ChangePinNative(
                        readerBytes,
                        (nuint)readerBytes.Length,
                        serialBytes,
                        (nuint)serialBytes.Length,
                        (byte)slot,
                        currentBytes,
                        (nuint)currentBytes.Length,
                        newBytes,
                        (nuint)newBytes.Length,
                        confirmationBytes,
                        (nuint)confirmationBytes.Length
                    ),
                LocalCardJsonContext.Default.NativeEnvelopeMutationResult
            );
        }
        finally
        {
            Zero(readerBytes, serialBytes, currentBytes, newBytes, confirmationBytes);
        }
    }

    internal static MutationResult UnblockPin(
        string reader,
        string serial,
        PinSlot slot,
        string puk,
        string newPin,
        string confirmation
    )
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        byte[] serialBytes = Encoding.UTF8.GetBytes(serial);
        byte[] pukBytes = Encoding.ASCII.GetBytes(puk);
        byte[] newBytes = Encoding.ASCII.GetBytes(newPin);
        byte[] confirmationBytes = Encoding.ASCII.GetBytes(confirmation);
        try
        {
            return Invoke(
                () =>
                    UnblockPinNative(
                        readerBytes,
                        (nuint)readerBytes.Length,
                        serialBytes,
                        (nuint)serialBytes.Length,
                        (byte)slot,
                        pukBytes,
                        (nuint)pukBytes.Length,
                        newBytes,
                        (nuint)newBytes.Length,
                        confirmationBytes,
                        (nuint)confirmationBytes.Length
                    ),
                LocalCardJsonContext.Default.NativeEnvelopeMutationResult
            );
        }
        finally
        {
            Zero(readerBytes, serialBytes, pukBytes, newBytes, confirmationBytes);
        }
    }

    internal static MutationResult Activate(
        string reader,
        string serial,
        string activationCode,
        string newPin1,
        string pin1Confirmation,
        string newPin2,
        string pin2Confirmation,
        bool allowReactivate
    )
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        byte[] serialBytes = Encoding.UTF8.GetBytes(serial);
        byte[] activationBytes = Encoding.ASCII.GetBytes(activationCode);
        byte[] pin1Bytes = Encoding.ASCII.GetBytes(newPin1);
        byte[] pin1ConfirmationBytes = Encoding.ASCII.GetBytes(pin1Confirmation);
        byte[] pin2Bytes = Encoding.ASCII.GetBytes(newPin2);
        byte[] pin2ConfirmationBytes = Encoding.ASCII.GetBytes(pin2Confirmation);
        try
        {
            return Invoke(
                () =>
                    ActivateNative(
                        readerBytes,
                        (nuint)readerBytes.Length,
                        serialBytes,
                        (nuint)serialBytes.Length,
                        activationBytes,
                        (nuint)activationBytes.Length,
                        pin1Bytes,
                        (nuint)pin1Bytes.Length,
                        pin1ConfirmationBytes,
                        (nuint)pin1ConfirmationBytes.Length,
                        pin2Bytes,
                        (nuint)pin2Bytes.Length,
                        pin2ConfirmationBytes,
                        (nuint)pin2ConfirmationBytes.Length,
                        allowReactivate ? (byte)1 : (byte)0
                    ),
                LocalCardJsonContext.Default.NativeEnvelopeMutationResult
            );
        }
        finally
        {
            Zero(
                readerBytes,
                serialBytes,
                activationBytes,
                pin1Bytes,
                pin1ConfirmationBytes,
                pin2Bytes,
                pin2ConfirmationBytes
            );
        }
    }

    private static void Zero(params byte[][] buffers)
    {
        foreach (byte[] buffer in buffers)
        {
            CryptographicOperations.ZeroMemory(buffer);
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
