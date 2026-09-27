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

/// <summary>The native JSON envelope: exactly one of data or error.</summary>
internal sealed class NativeEnvelope<T>
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    [JsonPropertyName("data")]
    public T? Data { get; init; }

    [JsonPropertyName("error")]
    public NativeError? Error { get; init; }
}

/// <summary>A stable native failure name and message.</summary>
internal sealed class NativeError
{
    [JsonPropertyName("code")]
    public string Code { get; init; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; init; } = string.Empty;
}

/// <summary>A live offer's handle, the QR text encoding it, and the 6-digit numeric pairing code.</summary>
internal sealed class BeginPairingResult
{
    [JsonPropertyName("handle")]
    public ulong Handle { get; init; }

    [JsonPropertyName("offer_uri")]
    public string OfferUri { get; init; } = string.Empty;

    [JsonPropertyName("pairing_code")]
    public string PairingCode { get; init; } = string.Empty;
}

/// <summary>The current pairing state, plus the peer once it connects.</summary>
internal sealed class PairingState
{
    [JsonPropertyName("state")]
    public string State { get; init; } = string.Empty;

    [JsonPropertyName("peer")]
    public PairingPeer? Peer { get; init; }

    [JsonPropertyName("pair_id_hex")]
    public string? PairIdHex { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }
}

/// <summary>The authenticated peer's self-declared labels and requested profiles.</summary>
internal sealed class PairingPeer
{
    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = string.Empty;

    [JsonPropertyName("platform")]
    public string Platform { get; init; } = string.Empty;

    [JsonPropertyName("profiles")]
    public IReadOnlyList<string> Profiles { get; init; } = [];
}

/// <summary>An acknowledged native call with no payload of its own.</summary>
internal sealed class Acknowledgement
{
    [JsonPropertyName("ok")]
    public bool Ok { get; init; }
}

/// <summary>One remote card reading: the holder identity.</summary>
internal sealed class CardReading
{
    [JsonPropertyName("identity")]
    public CardIdentity Identity { get; init; } = new();
}

/// <summary>The public identity fields from the card.</summary>
internal sealed class CardIdentity
{
    [JsonPropertyName("display_name")]
    public string DisplayName { get; init; } = string.Empty;

    [JsonPropertyName("person_id")]
    public string PersonId { get; init; } = string.Empty;
}

/// <summary>Reflection-free serialization metadata for the RAPP boundary.</summary>
[JsonSourceGenerationOptions(PropertyNameCaseInsensitive = false)]
[JsonSerializable(typeof(NativeEnvelope<BeginPairingResult>))]
[JsonSerializable(typeof(NativeEnvelope<PairingState>))]
[JsonSerializable(typeof(NativeEnvelope<Acknowledgement>))]
[JsonSerializable(typeof(NativeEnvelope<CardReading>))]
[JsonSerializable(typeof(IReadOnlyList<string>))]
internal sealed partial class RappJsonContext : JsonSerializerContext;
