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

// The RAPP bridge DLL ships beside the executable; resolve native libraries
// only from the safe default directory set, which includes the application
// directory and System32, rather than the ambient search path.
[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
