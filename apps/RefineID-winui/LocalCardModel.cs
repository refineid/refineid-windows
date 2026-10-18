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

using System.Text.Json.Serialization;

/// <summary>The two user PINs of a FINEID card, as the native layer numbers them.</summary>
internal enum PinSlot : byte
{
    Pin1 = 1,
    Pin2 = 2,
}

/// <summary>The document formats the card signs, as the native service numbers them.</summary>
internal enum DocumentFormat : byte
{
    Pades = 1,
    AsicE = 2,
}

/// <summary>What the document page is opened for.</summary>
internal enum DocumentMode
{
    Verify,
    Sign,
}

/// <summary>A verified container: its verdict and the report as text.</summary>
internal sealed class ContainerVerifyReport
{
    [JsonPropertyName("container")]
    public string Container { get; init; } = string.Empty;

    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    [JsonPropertyName("report")]
    public string Report { get; init; } = string.Empty;
}

/// <summary>A signed document: where it was written and what signed it.</summary>
internal sealed class DocumentSignReport
{
    [JsonPropertyName("output_path")]
    public string OutputPath { get; init; } = string.Empty;

    [JsonPropertyName("output_len")]
    public long OutputLength { get; init; }

    [JsonPropertyName("slot")]
    public string Slot { get; init; } = string.Empty;

    [JsonPropertyName("signer_cn")]
    public string? SignerCommonName { get; init; }

    [JsonPropertyName("verified")]
    public bool Verified { get; init; }

    [JsonPropertyName("local_verify")]
    public string LocalVerify { get; init; } = string.Empty;
}

/// <summary>Reader list result from settings FFI.</summary>
internal sealed class ReaderList
{
    [JsonPropertyName("readers")]
    public IReadOnlyList<string> Readers { get; init; } = [];
}

/// <summary>Status of a PIN or PUK credential.</summary>
internal sealed class CredentialStatus
{
    [JsonPropertyName("state")]
    public string State { get; init; } = "unknown";

    [JsonPropertyName("attempts_remaining")]
    public byte? AttemptsRemaining { get; init; }

    [JsonPropertyName("status_word")]
    public ushort? StatusWord { get; init; }
}

/// <summary>Snapshot of a local card returned by card-manager inspection.</summary>
internal sealed class LocalCardSnapshot
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

/// <summary>What a PACE-protected contactless session reports about the card.</summary>
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

/// <summary>The outcome of a PIN change, PIN reset, or card activation.</summary>
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

/// <summary>Reflection-free serialization metadata for the Local Card boundary.</summary>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = false)]
[JsonSerializable(typeof(NativeEnvelope<ReaderList>))]
[JsonSerializable(typeof(NativeEnvelope<LocalCardSnapshot>))]
[JsonSerializable(typeof(NativeEnvelope<LocalCardSupport>))]
[JsonSerializable(typeof(NativeEnvelope<ContactlessSnapshot>))]
[JsonSerializable(typeof(NativeEnvelope<MutationResult>))]
[JsonSerializable(typeof(NativeEnvelope<ContainerVerifyReport>))]
[JsonSerializable(typeof(NativeEnvelope<DocumentSignReport>))]
internal sealed partial class LocalCardJsonContext : JsonSerializerContext;

/// Mirror of the settings-ffi JSON for the local-card lane probe.
internal sealed class LocalCardSupport
{
    [JsonPropertyName("state")]
    public string State { get; init; } = "unknown";

    [JsonPropertyName("reader_count")]
    public int? ReaderCount { get; init; }
}
