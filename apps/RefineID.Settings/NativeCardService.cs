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

using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RefineID_Settings;

internal enum PinSlot : byte
{
    Pin1 = 1,
    Pin2 = 2,
}

internal sealed class NativeCardException(string code, string message) : Exception(message)
{
    internal string Code { get; } = code;
}

internal sealed class ReaderList
{
    [JsonPropertyName("readers")]
    public string[] Readers { get; init; } = [];
}

internal sealed class LocalCardSupport
{
    [JsonPropertyName("state")]
    public string State { get; init; } = "unknown";

    [JsonPropertyName("reader_count")]
    public int? ReaderCount { get; init; }
}

internal sealed class CredentialStatus
{
    [JsonPropertyName("state")]
    public string State { get; init; } = "unknown";

    [JsonPropertyName("attempts_remaining")]
    public byte? AttemptsRemaining { get; init; }

    [JsonPropertyName("status_word")]
    public ushort? StatusWord { get; init; }
}

internal sealed class CardSnapshot
{
    [JsonPropertyName("reader")]
    public string Reader { get; init; } = string.Empty;

    [JsonPropertyName("serial")]
    public string Serial { get; init; } = string.Empty;

    [JsonPropertyName("person")]
    public string Person { get; init; } = string.Empty;

    [JsonPropertyName("model")]
    public string Model { get; init; } = string.Empty;

    [JsonPropertyName("generation")]
    public string Generation { get; init; } = "unknown";

    [JsonPropertyName("activation_code_length")]
    public int? ActivationCodeLength { get; init; }

    [JsonPropertyName("pin1")]
    public CredentialStatus? Pin1 { get; init; }

    [JsonPropertyName("pin2")]
    public CredentialStatus? Pin2 { get; init; }

    [JsonPropertyName("puk")]
    public CredentialStatus? Puk { get; init; }

    [JsonPropertyName("pin1_changed")]
    public bool? Pin1Changed { get; init; }

    [JsonPropertyName("pin2_changed")]
    public bool? Pin2Changed { get; init; }
}

internal sealed class ContactlessSnapshot
{
    [JsonPropertyName("reader")]
    public string Reader { get; init; } = string.Empty;

    [JsonPropertyName("serial")]
    public string Serial { get; init; } = string.Empty;

    [JsonPropertyName("person")]
    public string Person { get; init; } = string.Empty;

    [JsonPropertyName("generation")]
    public string Generation { get; init; } = "unknown";

    [JsonPropertyName("pin1")]
    public CredentialStatus? Pin1 { get; init; }

    [JsonPropertyName("pin2")]
    public CredentialStatus? Pin2 { get; init; }

    [JsonPropertyName("puk")]
    public CredentialStatus? Puk { get; init; }
}

internal sealed class MutationResult
{
    [JsonPropertyName("succeeded")]
    public bool Succeeded { get; init; }

    [JsonPropertyName("outcome")]
    public string Outcome { get; init; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;

    [JsonPropertyName("attempts_remaining")]
    public byte? AttemptsRemaining { get; init; }

    [JsonPropertyName("status_word")]
    public ushort? StatusWord { get; init; }
}

internal static class NativeCardService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = false,
    };

    internal static string[] PresentReaders()
    {
        return Invoke<ReaderList>(NativeMethods.PresentReaders).Readers;
    }

    internal static LocalCardSupport DetectLocalCardSupport()
    {
        return Invoke<LocalCardSupport>(NativeMethods.DetectLocalCardSupport);
    }

    internal static CardSnapshot Inspect(string reader)
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        try
        {
            return Invoke<CardSnapshot>(() =>
                NativeMethods.Inspect(readerBytes, (nuint)readerBytes.Length)
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readerBytes);
        }
    }

    internal static ContactlessSnapshot PrimeContactless(string reader, string can)
    {
        byte[] readerBytes = Encoding.UTF8.GetBytes(reader);
        byte[] canBytes = Encoding.ASCII.GetBytes(can);
        try
        {
            return Invoke<ContactlessSnapshot>(() =>
                NativeMethods.PrimeContactless(
                    readerBytes,
                    (nuint)readerBytes.Length,
                    canBytes,
                    (nuint)canBytes.Length
                )
            );
        }
        finally
        {
            CryptographicOperations.ZeroMemory(readerBytes);
            CryptographicOperations.ZeroMemory(canBytes);
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
            return Invoke<MutationResult>(() =>
                NativeMethods.ChangePin(
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
                )
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
            return Invoke<MutationResult>(() =>
                NativeMethods.UnblockPin(
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
                )
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
            return Invoke<MutationResult>(() =>
                NativeMethods.Activate(
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
                )
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

    private static T Invoke<T>(Func<nint> operation)
    {
        nint response = operation();
        if (response == nint.Zero)
        {
            throw new NativeCardException(
                "native_allocation_failed",
                "The native card service did not return a response."
            );
        }

        try
        {
            string json =
                Marshal.PtrToStringUTF8(response)
                ?? throw new NativeCardException(
                    "native_response_invalid",
                    "The native card service returned invalid UTF-8."
                );
            NativeEnvelope<T> envelope =
                JsonSerializer.Deserialize<NativeEnvelope<T>>(json, JsonOptions)
                ?? throw new NativeCardException(
                    "native_response_invalid",
                    "The native card service returned invalid JSON."
                );
            if (!envelope.Ok)
            {
                throw new NativeCardException(
                    envelope.Error?.Code ?? "native_error",
                    envelope.Error?.Message ?? "The native card service failed."
                );
            }

            return envelope.Data
                ?? throw new NativeCardException(
                    "native_response_empty",
                    "The native card service returned no data."
                );
        }
        finally
        {
            NativeMethods.StringFree(response);
        }
    }

    private static void Zero(params byte[][] buffers)
    {
        foreach (byte[] buffer in buffers)
        {
            CryptographicOperations.ZeroMemory(buffer);
        }
    }

    private sealed class NativeEnvelope<T>
    {
        [JsonPropertyName("ok")]
        public bool Ok { get; init; }

        [JsonPropertyName("data")]
        public T? Data { get; init; }

        [JsonPropertyName("error")]
        public NativeError? Error { get; init; }
    }

    private sealed class NativeError
    {
        [JsonPropertyName("code")]
        public string Code { get; init; } = string.Empty;

        [JsonPropertyName("message")]
        public string Message { get; init; } = string.Empty;
    }

    private static class NativeMethods
    {
        private const string Library = "refineid_settings_ffi";

        [DllImport(Library, EntryPoint = "refineid_settings_present_readers")]
        internal static extern nint PresentReaders();

        [DllImport(Library, EntryPoint = "refineid_settings_detect_local_card_support")]
        internal static extern nint DetectLocalCardSupport();

        [DllImport(Library, EntryPoint = "refineid_settings_inspect")]
        internal static extern nint Inspect([In] byte[] reader, nuint readerLength);

        [DllImport(Library, EntryPoint = "refineid_settings_prime_contactless")]
        internal static extern nint PrimeContactless(
            [In] byte[] reader,
            nuint readerLength,
            [In] byte[] can,
            nuint canLength
        );

        [DllImport(Library, EntryPoint = "refineid_settings_change_pin")]
        internal static extern nint ChangePin(
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

        [DllImport(Library, EntryPoint = "refineid_settings_unblock_pin")]
        internal static extern nint UnblockPin(
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

        [DllImport(Library, EntryPoint = "refineid_settings_activate")]
        internal static extern nint Activate(
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

        [DllImport(Library, EntryPoint = "refineid_settings_string_free")]
        internal static extern void StringFree(nint value);
    }
}
