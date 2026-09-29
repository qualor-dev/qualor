import { lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import { CliError, EXIT } from '../errors';

/** config.md §6.1: the first line of the only file Qualor ever writes to or removes there. */
export const HOOK_MARKER = '<!-- qualor-dotnet-hook v2 -->';
/**
 * Task 4: v1 (no Sonar family) is still recognised as Qualor's own, so `installHook` still
 * replaces it (with the current version) and `removeHook` still removes it, instead of treating a
 * hook left by an earlier CLI as a foreign file.
 */
const HOOK_MARKER_V1 = '<!-- qualor-dotnet-hook v1 -->';
export const HOOK_FILE = 'Qualor.ImportBefore.targets';

/**
 * MSBuild's user extensions directory (config.md §4): `QUALOR_MSBUILD_USER_DIR`, else what
 * MSBuild uses. On Windows MSBuild reads the known folder, which `LOCALAPPDATA` normally names
 * (probe P6). On Linux it honours an absolute `XDG_DATA_HOME`, else `~/.local/share`. On macOS,
 * since .NET 8, `Environment.SpecialFolder.LocalApplicationData` is `~/Library/Application
 * Support` (not `XDG_DATA_HOME`, which .NET on macOS does not read), so that is MSBuild's user
 * extensions path there too (ruling R6; not verified on a real Mac — set
 * `QUALOR_MSBUILD_USER_DIR` if it differs).
 */
export function msbuildUserDir(
  env: Readonly<Record<string, string | undefined>>,
  platform: NodeJS.Platform = process.platform,
  home: string = os.homedir(),
): string {
  const explicit = env['QUALOR_MSBUILD_USER_DIR'];
  if (explicit !== undefined && explicit !== '') {
    if (!path.isAbsolute(explicit)) {
      throw new CliError(EXIT.USAGE, 'QUALOR_MSBUILD_USER_DIR must be an absolute path');
    }
    return explicit;
  }
  if (platform === 'win32') {
    const local = env['LOCALAPPDATA'];
    const base = local !== undefined && local !== '' ? local : path.join(home, 'AppData', 'Local');
    return path.join(base, 'Microsoft', 'MSBuild');
  }
  if (platform === 'darwin') {
    return path.join(home, 'Library', 'Application Support', 'Microsoft', 'MSBuild');
  }
  const xdg = env['XDG_DATA_HOME'];
  const base = xdg !== undefined && path.isAbsolute(xdg) ? xdg : path.join(home, '.local', 'share');
  return path.join(base, 'Microsoft', 'MSBuild');
}

export function hookPath(userDir: string): string {
  return path.join(userDir, 'Current', 'Microsoft.Common.targets', 'ImportBefore', HOOK_FILE);
}

/** MSBuild's own escapes (`%XX`) for its special characters, then XML's. */
export function msbuildEscape(value: string): string {
  return value
    .replace(/[%;$@'?*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0')}`)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * The hook (config.md §6.1, probes P1–P4, P8, P9). Inert unless the project lies below a
 * `.qualor/dotnet/session.json` less than 24 hours old and is C#. The age is compared in whole
 * days (`TimeSpan.Days < 1`, exactly `TotalHours < 24`): MSBuild prints a double such as
 * TotalHours in exponent form for a young session (8.026275E-05), which its numeric comparison
 * refuses with MSB4086.
 */
export function hookText(): string {
  return `${HOOK_MARKER}
<!-- Installed by qualor dotnet begin and removed by qualor dotnet end (https://qualor.dev/docs/cli).
     Inert unless the project lies below a .qualor/dotnet/session.json less than 24 hours old. -->
<Project>
  <PropertyGroup>
    <_QualorRoot>$([MSBuild]::GetDirectoryNameOfFileAbove($(MSBuildProjectDirectory), .qualor/dotnet/session.json))</_QualorRoot>
    <_QualorSession Condition="'$(_QualorRoot)' != ''">$(_QualorRoot)/.qualor/dotnet</_QualorSession>
    <_QualorAgeDays Condition="'$(_QualorSession)' != ''">$([System.DateTime]::Now.Subtract($([System.IO.File]::GetLastWriteTime('$(_QualorSession)/session.json'))).Days)</_QualorAgeDays>
    <_QualorActive Condition="'$(_QualorSession)' != '' and '$(Language)' == 'C#' and $(_QualorAgeDays) &lt; 1">true</_QualorActive>
  </PropertyGroup>
  <Import Project="$(_QualorSession)/session.props" Condition="'$(_QualorActive)' == 'true' and Exists('$(_QualorSession)/session.props')" />
  <PropertyGroup Condition="'$(_QualorActive)' == 'true'">
    <RunAnalyzers>true</RunAnalyzers>
    <RunAnalyzersDuringBuild>true</RunAnalyzersDuringBuild>
    <AnalysisLevel>latest</AnalysisLevel>
    <AnalysisMode>All</AnalysisMode>
    <TreatWarningsAsErrors>false</TreatWarningsAsErrors>
    <CodeAnalysisTreatWarningsAsErrors>false</CodeAnalysisTreatWarningsAsErrors>
    <WarningsAsErrors></WarningsAsErrors>
    <MSBuildTreatWarningsAsErrors>false</MSBuildTreatWarningsAsErrors>
    <MSBuildWarningsAsErrors></MSBuildWarningsAsErrors>
    <_QualorHash>$([MSBuild]::StableStringHash('$(MSBuildProjectFullPath)|$(TargetFramework)'))</_QualorHash>
    <_QualorLog>$(_QualorSession)/sarif/$(MSBuildProjectName)-$(_QualorHash)-$(TargetFramework).sarif</_QualorLog>
  </PropertyGroup>
  <Target Name="_QualorBeforeCompile" BeforeTargets="CoreCompile" Condition="'$(_QualorActive)' == 'true'">
    <ItemGroup>
      <_QualorOwnRoslynator Include="@(Analyzer)" Condition="$([System.String]::Copy('%(Filename)').StartsWith('Roslynator.'))" />
      <_QualorOwnSonar Include="@(Analyzer)" Condition="$([System.String]::Copy('%(Filename)').StartsWith('SonarAnalyzer.'))" />
    </ItemGroup>
    <PropertyGroup>
      <ErrorLog>$(_QualorLog),version=2.1</ErrorLog>
      <TreatWarningsAsErrors>false</TreatWarningsAsErrors>
      <CodeAnalysisTreatWarningsAsErrors>false</CodeAnalysisTreatWarningsAsErrors>
      <WarningsAsErrors></WarningsAsErrors>
      <MSBuildTreatWarningsAsErrors>false</MSBuildTreatWarningsAsErrors>
      <MSBuildWarningsAsErrors></MSBuildWarningsAsErrors>
    </PropertyGroup>
    <ItemGroup Condition="'@(_QualorOwnRoslynator)' == ''">
      <Analyzer Include="@(QualorBundledAnalyzer)" />
    </ItemGroup>
    <ItemGroup Condition="'@(_QualorOwnSonar)' == ''">
      <Analyzer Include="@(QualorBundledSonarAnalyzer)" />
    </ItemGroup>
  </Target>
  <Target Name="_QualorRecord" AfterTargets="CoreCompile" Condition="'$(_QualorActive)' == 'true'">
    <WriteLinesToFile File="$(_QualorSession)/projects/$(_QualorHash).txt" Lines="$([MSBuild]::Escape('$(MSBuildProjectFullPath)'));$([MSBuild]::Escape('$(TargetFramework)'));$([MSBuild]::Escape('$(_QualorLog)'))" Overwrite="true" />
  </Target>
</Project>
`;
}

/**
 * `null` when nothing was positively found at `file`: it is absent (`ENOENT`), or a path
 * component above it is not a directory (`ENOTDIR` — a plain file blocking `Current/` or
 * `Microsoft.Common.targets/`, for example), so the path cannot be reached at all. Node reports
 * that second case as `ENOENT` on Windows and `ENOTDIR` on Linux for the same situation (checked
 * directly); either way `installHook` falls through to its ordinary `mkdirSync`/write, which fails
 * with the same OS error and lets `begin` treat it as "the hook cannot be written" (config.md
 * §6.1: warn and exit 0 under `auto`, exit 3 under `enabled: true`), not as a foreign file at the
 * hook's own path (exit 2, config.md §6.1 step 2). Any other failure to inspect it (a permission
 * error reaching the path, an unreadable file once it is confirmed to be one) is treated as
 * `false` — a file Qualor cannot positively identify as its own is foreign, so `installHook` never
 * renames over something it could not read.
 */
function isOurs(file: string): boolean | null {
  try {
    const stat = lstatSync(file);
    if (!stat.isFile()) return false;
    const text = readFileSync(file, 'utf8');
    return text.startsWith(HOOK_MARKER) || text.startsWith(HOOK_MARKER_V1);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    return code === 'ENOENT' || code === 'ENOTDIR' ? null : false;
  }
}

/**
 * Writes the hook atomically: a uniquely-named temporary file next to
 * `Current/Microsoft.Common.targets/ImportBefore/` (MSBuild only imports files inside that
 * directory, not beside it), on the same file system so the rename stays atomic, then a rename
 * over the target. On any failure — the write or the rename — the temporary file is removed and
 * the error is rethrown, so a failed install never leaves a stray or truncated file where MSBuild
 * would read it.
 */
export function installHook(userDir: string): void {
  const file = hookPath(userDir);
  if (isOurs(file) === false) {
    throw new CliError(
      EXIT.USAGE,
      `${file} exists and is not Qualor's (no ${HOOK_MARKER} marker); remove it or set QUALOR_MSBUILD_USER_DIR`,
    );
  }
  const importBefore = path.dirname(file);
  mkdirSync(importBefore, { recursive: true });
  const temp = path.join(
    path.dirname(importBefore),
    `.${HOOK_FILE}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`,
  );
  try {
    writeFileSync(temp, hookText(), { flag: 'wx' });
    renameSync(temp, file);
  } catch (err) {
    rmSync(temp, { force: true });
    throw err;
  }
}

/** Removes the hook when it is Qualor's; true when a file was removed. */
export function removeHook(userDir: string): boolean {
  const file = hookPath(userDir);
  if (isOurs(file) !== true) return false;
  rmSync(file, { force: true });
  return true;
}
