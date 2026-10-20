# Copyright 2026 Petri Koistinen
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

<#
.SYNOPSIS
Signs one random digest through a RefineID key storage provider DLL, the way
a browser's TLS client authentication does, and verifies the signature.

.DESCRIPTION
Loads the provider DLL given (a fresh build, not the installed one), takes
its CNG function table from GetKeyStorageInterface, opens the provider,
enumerates its keys and calls SignHash on the first one with a random
SHA-256 digest: ECDSA for an EC key, PKCS#1 v1.5 for an RSA key. The
provider asks the user's RefineID agent over the agent pipe, so the agent
must be running and hold the paired phone's session.

The signature is verified again here with .NET against the public key of the
"RefineID (phone)" certificate in CurrentUser\My, independently of the
provider's own check. Nothing personal is printed: the key is named by its
algorithm group, the signature by its length.

Exit codes: 0 signed and verified, 1 failure, 2 the provider refused
(no agent, no phone, declined, or a signature that does not verify).

.EXAMPLE
pwsh scripts/test-ksp-remote-sign.ps1 -DllPath target/debug/refineid_minidriver.dll
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$DllPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$dll = (Resolve-Path $DllPath).Path
$source = @'
using System;
using System.Runtime.InteropServices;

public static class KspProbe
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern IntPtr LoadLibraryW(string path);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
    static extern IntPtr GetProcAddress(IntPtr module, string name);

    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    delegate int GetInterface(string name, out IntPtr table, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    delegate int OpenProvider(out IntPtr provider, string name, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    delegate int OpenKey(IntPtr provider, out IntPtr key, string name, uint keySpec, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    delegate int GetKeyProperty(IntPtr provider, IntPtr key, string property, byte[] output, uint size, out uint result, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate int EnumKeys(IntPtr provider, IntPtr scope, out IntPtr keyName, ref IntPtr state, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    delegate int SignHash(IntPtr provider, IntPtr key, IntPtr padding, byte[] hash, uint hashSize, byte[] signature, uint signatureSize, out uint result, uint flags);

    const int OpenProviderSlot = 0;
    const int OpenKeySlot = 1;
    const int GetKeyPropertySlot = 4;
    const int EnumKeysSlot = 16;
    const int SignHashSlot = 19;
    const int FirstSlotOffset = 8;
    const uint PadPkcs1 = 0x2;

    static T Slot<T>(IntPtr table, int slot)
    {
        IntPtr entry = Marshal.ReadIntPtr(table, FirstSlotOffset + slot * IntPtr.Size);
        return (T)(object)Marshal.GetDelegateForFunctionPointer(entry, typeof(T));
    }

    public static string Group;
    public static byte[] Digest;
    public static byte[] Signature;

    public static int Run(string dll, string providerName)
    {
        IntPtr module = LoadLibraryW(dll);
        if (module == IntPtr.Zero) throw new Exception("LoadLibrary failed: " + Marshal.GetLastWin32Error());
        var getInterface = (GetInterface)Marshal.GetDelegateForFunctionPointer(
            GetProcAddress(module, "GetKeyStorageInterface"), typeof(GetInterface));
        IntPtr table;
        int status = getInterface(providerName, out table, 0);
        if (status != 0) throw new Exception("GetKeyStorageInterface: 0x" + status.ToString("X8"));
        IntPtr provider;
        status = Slot<OpenProvider>(table, OpenProviderSlot)(out provider, providerName, 0);
        if (status != 0) throw new Exception("OpenProvider: 0x" + status.ToString("X8"));
        IntPtr keyName; IntPtr state = IntPtr.Zero;
        status = Slot<EnumKeys>(table, EnumKeysSlot)(provider, IntPtr.Zero, out keyName, ref state, 0);
        if (status != 0) throw new Exception("EnumKeys found no key: 0x" + status.ToString("X8"));
        // NCryptKeyName: pszName first.
        string name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(keyName));
        IntPtr key;
        status = Slot<OpenKey>(table, OpenKeySlot)(provider, out key, name, 0, 0);
        if (status != 0) throw new Exception("OpenKey: 0x" + status.ToString("X8"));
        byte[] group = new byte[64]; uint groupSize;
        status = Slot<GetKeyProperty>(table, GetKeyPropertySlot)(provider, key, "Algorithm Group", group, (uint)group.Length, out groupSize, 0);
        if (status != 0) throw new Exception("GetKeyProperty: 0x" + status.ToString("X8"));
        Group = System.Text.Encoding.Unicode.GetString(group, 0, (int)groupSize).TrimEnd('\0');
        Digest = new byte[32];
        new Random().NextBytes(Digest);
        using (var sha = System.Security.Cryptography.SHA256.Create()) Digest = sha.ComputeHash(Digest);
        IntPtr padding = IntPtr.Zero; uint flags = 0;
        if (Group == "RSA")
        {
            padding = Marshal.AllocHGlobal(IntPtr.Size);
            Marshal.WriteIntPtr(padding, Marshal.StringToHGlobalUni("SHA256"));
            flags = PadPkcs1;
        }
        uint needed;
        status = Slot<SignHash>(table, SignHashSlot)(provider, key, padding, Digest, (uint)Digest.Length, null, 0, out needed, flags);
        if (status != 0) throw new Exception("SignHash size query: 0x" + status.ToString("X8"));
        byte[] signature = new byte[needed];
        status = Slot<SignHash>(table, SignHashSlot)(provider, key, padding, Digest, (uint)Digest.Length, signature, needed, out needed, flags);
        if (status != 0) return status;
        Signature = new byte[needed];
        Array.Copy(signature, Signature, needed);
        return 0;
    }
}
'@
Add-Type -TypeDefinition $source

Write-Host "signing a random SHA-256 digest through $([IO.Path]::GetFileName($dll)); approve on the phone if it asks"
$started = Get-Date
$status = [KspProbe]::Run($dll, 'RefineID Key Storage Provider')
$seconds = [math]::Round(((Get-Date) - $started).TotalSeconds, 1)
if ($status -ne 0) {
    Write-Host ("the provider refused after {0} s: 0x{1:X8}" -f $seconds, $status)
    exit 2
}
Write-Host "key: $([KspProbe]::Group); signature: $([KspProbe]::Signature.Length) bytes after $seconds s"

$certificate = Get-ChildItem Cert:\CurrentUser\My |
    Where-Object FriendlyName -eq 'RefineID (phone)' |
    Select-Object -First 1
if (-not $certificate) {
    Write-Host 'no RefineID (phone) certificate is offered; is the agent running?'
    exit 1
}
$verified = if ([KspProbe]::Group -eq 'RSA') {
    [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate).VerifyHash(
        [KspProbe]::Digest, [KspProbe]::Signature,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
} else {
    [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($certificate).VerifyHash(
        [KspProbe]::Digest, [KspProbe]::Signature)
}
if ($verified) {
    Write-Host 'the signature verifies against the offered certificate'
    exit 0
}
Write-Host 'the signature does NOT verify against the offered certificate'
exit 1
