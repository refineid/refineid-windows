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

using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;

/// <summary>Coarse failure carried across the RAPP native boundary.</summary>
internal sealed class NativeRappException : Exception
{
    /// <summary>Stable failure name from the native layer.</summary>
    internal string Code { get; } = "native_error";

    internal NativeRappException(string code, string message)
        : base(message) => this.Code = code;

    internal NativeRappException()
        : base("The remote-card service failed.") { }

    internal NativeRappException(string message)
        : base(message) { }

    internal NativeRappException(string message, Exception innerException)
        : base(message, innerException) { }
}

/// <summary>
/// The narrow managed side of the RAPP requester C ABI. Source-generated
/// <c>LibraryImport</c> stubs and source-generated JSON keep the boundary
/// reflection-free. Every native call returns a UTF-8 JSON envelope that is
/// deserialized and freed exactly once.
/// </summary>
internal static partial class NativeRappService
{
    private const string Library = "refineid_rapp_ffi";

    [LibraryImport(Library, EntryPoint = "refineid_rapp_begin_pairing")]
    private static partial nint BeginPairingNative(
        [In] byte[] listen,
        nuint listenLength,
        [In] byte[] advertise,
        nuint advertiseLength,
        [In] byte[] name,
        nuint nameLength
    );

    [LibraryImport(Library, EntryPoint = "refineid_rapp_poll_pairing")]
    private static partial nint PollPairingNative(ulong handle);

    [LibraryImport(Library, EntryPoint = "refineid_rapp_confirm_pairing")]
    private static partial nint ConfirmPairingNative(
        ulong handle,
        [In] byte[] granted,
        nuint grantedLength
    );

    [LibraryImport(Library, EntryPoint = "refineid_rapp_cancel_pairing")]
    private static partial nint CancelPairingNative(ulong handle);

    [LibraryImport(Library, EntryPoint = "refineid_rapp_forget_pairings")]
    private static partial nint ForgetPairingsNative();

    [LibraryImport(Library, EntryPoint = "refineid_rapp_end_pairing")]
    private static partial void EndPairingNative(ulong handle);

    [LibraryImport(Library, EntryPoint = "refineid_rapp_read_card")]
    private static partial nint ReadCardNative(ulong handle);

    [LibraryImport(Library, EntryPoint = "refineid_rapp_string_free")]
    private static partial void StringFree(nint value);

    /// <summary>Starts a pairing offer and returns its handle and QR text.</summary>
    internal static BeginPairingResult BeginPairing(string listen, string advertise, string name)
    {
        byte[] listenBytes = Encoding.UTF8.GetBytes(listen);
        byte[] advertiseBytes = Encoding.UTF8.GetBytes(advertise);
        byte[] nameBytes = Encoding.UTF8.GetBytes(name);
        return Invoke(
            () =>
                BeginPairingNative(
                    listenBytes,
                    (nuint)listenBytes.Length,
                    advertiseBytes,
                    (nuint)advertiseBytes.Length,
                    nameBytes,
                    (nuint)nameBytes.Length
                ),
            RappJsonContext.Default.NativeEnvelopeBeginPairingResult
        );
    }

    /// <summary>Reads the current pairing state for the handle.</summary>
    internal static PairingState PollPairing(ulong handle) =>
        Invoke(() => PollPairingNative(handle), RappJsonContext.Default.NativeEnvelopePairingState);

    /// <summary>
    /// Approves the pairing. An empty list is sent as a zero-length buffer,
    /// which the native side reads as "grant exactly what the peer requested".
    /// </summary>
    internal static void ConfirmPairing(ulong handle, IReadOnlyList<string> granted)
    {
        byte[] grantedBytes =
            granted.Count == 0
                ? []
                : JsonSerializer.SerializeToUtf8Bytes(
                    granted,
                    RappJsonContext.Default.IReadOnlyListString
                );
        _ = Invoke(
            () => ConfirmPairingNative(handle, grantedBytes, (nuint)grantedBytes.Length),
            RappJsonContext.Default.NativeEnvelopeAcknowledgement
        );
    }

    /// <summary>Denies the pairing and drops the offer.</summary>
    internal static void CancelPairing(ulong handle) =>
        _ = Invoke(
            () => CancelPairingNative(handle),
            RappJsonContext.Default.NativeEnvelopeAcknowledgement
        );

    /// <summary>Forgets every stored pairing, clearing the device-only credential.</summary>
    internal static void ForgetPairings() =>
        _ = Invoke(
            () => ForgetPairingsNative(),
            RappJsonContext.Default.NativeEnvelopeAcknowledgement
        );

    /// <summary>Releases the handle and its background resources.</summary>
    internal static void EndPairing(ulong handle) => EndPairingNative(handle);

    /// <summary>Connects to the paired card and reads its public status, identity, and certificate.</summary>
    internal static CardReading ReadCard(ulong handle) =>
        Invoke(() => ReadCardNative(handle), RappJsonContext.Default.NativeEnvelopeCardReading);

    private static T Invoke<T>(Func<nint> operation, JsonTypeInfo<NativeEnvelope<T>> envelopeInfo)
    {
        nint response = operation();
        if (response == nint.Zero)
        {
            throw new NativeRappException(
                "native_allocation_failed",
                "The remote-card service did not respond."
            );
        }

        try
        {
            string json =
                Marshal.PtrToStringUTF8(response)
                ?? throw new NativeRappException(
                    "native_response_invalid",
                    "The remote-card response was not valid UTF-8."
                );
            NativeEnvelope<T> envelope =
                JsonSerializer.Deserialize(json, envelopeInfo)
                ?? throw new NativeRappException(
                    "native_response_invalid",
                    "The remote-card response was not valid JSON."
                );
            if (!envelope.Ok)
            {
                throw new NativeRappException(
                    envelope.Error?.Code ?? "native_error",
                    envelope.Error?.Message ?? "The remote-card service failed."
                );
            }

            return envelope.Data
                ?? throw new NativeRappException(
                    "native_response_empty",
                    "The remote-card response carried no data."
                );
        }
        finally
        {
            StringFree(response);
        }
    }
}
