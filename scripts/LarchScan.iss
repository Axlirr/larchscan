#ifndef MyAppVersion
  #define MyAppVersion "0.4.0"
#endif

#ifndef StageDir
  #define StageDir "..\dist\larchscan-0.4.0-windows-x64"
#endif

#ifndef OutDir
  #define OutDir "..\dist"
#endif

[Setup]
AppId={{8E9B7D42-5C31-4F26-A914-7B2E61C4D803}
AppName=LarchScan
AppVersion={#MyAppVersion}
AppVerName=LarchScan {#MyAppVersion}
AppPublisher=LarchScan Contributors
AppPublisherURL=https://github.com/Axlirr/larchscan
AppSupportURL=https://github.com/Axlirr/larchscan/issues
AppUpdatesURL=https://github.com/Axlirr/larchscan/releases
DefaultDirName={autopf}\LarchScan
DefaultGroupName=LarchScan
DisableProgramGroupPage=yes
LicenseFile={#StageDir}\LICENSE
OutputDir={#OutDir}
OutputBaseFilename=LarchScan-{#MyAppVersion}-Setup
SetupIconFile=..\assets\larchscan.ico
UninstallDisplayIcon={app}\LarchScan.exe
UninstallDisplayName=LarchScan
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={#MyAppVersion}.0
VersionInfoProductName=LarchScan
VersionInfoDescription=LarchScan Windows Installer
ChangesEnvironment=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Add LarchScan CLI (tools\larchscan.exe) to user PATH"; GroupDescription: "Command-line integration:"; Flags: unchecked

[Files]
Source: "{#StageDir}\LarchScan.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\tools\larchscan.exe"; DestDir: "{app}\tools"; Flags: ignoreversion
Source: "{#StageDir}\examples\demo.txt"; DestDir: "{app}\examples"; Flags: ignoreversion
Source: "{#StageDir}\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\THIRD-PARTY-NOTICES.txt"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\LarchScan"; Filename: "{app}\LarchScan.exe"; Comment: "Inspect files, understand findings, and manage quarantine"
Name: "{autodesktop}\LarchScan"; Filename: "{app}\LarchScan.exe"; Tasks: desktopicon; Comment: "Inspect files, understand findings, and manage quarantine"

[Run]
Filename: "{app}\LarchScan.exe"; Description: "{cm:LaunchProgram,LarchScan}"; Flags: nowait postinstall skipifsilent

[Code]
const
  EnvKey = 'Environment';

function PathContainsEntry(const Paths, Entry: string): Boolean;
var
  UpperPaths, UpperEntry: string;
begin
  UpperPaths := ';' + UpperCase(Paths) + ';';
  UpperEntry := ';' + UpperCase(Entry) + ';';
  Result := Pos(UpperEntry, UpperPaths) > 0;
end;

procedure AddToUserPath(const Entry: string);
var
  Paths: string;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', Paths) then
    Paths := '';
  if PathContainsEntry(Paths, Entry) then
    Exit;
  if (Length(Paths) > 0) and (Paths[Length(Paths)] <> ';') then
    Paths := Paths + ';';
  Paths := Paths + Entry;
  RegWriteExpandStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', Paths);
end;

procedure RemoveFromUserPath(const Entry: string);
var
  Paths, UpperPaths, UpperEntry: string;
  P: Integer;
begin
  if not RegQueryStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', Paths) then
    Exit;
  UpperPaths := ';' + UpperCase(Paths) + ';';
  UpperEntry := ';' + UpperCase(Entry) + ';';
  P := Pos(UpperEntry, UpperPaths);
  if P = 0 then
    Exit;
  Delete(Paths, P, Length(Entry) + 1);
  if (Length(Paths) > 0) and (Paths[Length(Paths)] = ';') then
    Delete(Paths, Length(Paths), 1);
  if (Length(Paths) > 0) and (Paths[1] = ';') then
    Delete(Paths, 1, 1);
  RegWriteExpandStringValue(HKEY_CURRENT_USER, EnvKey, 'Path', Paths);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if (CurStep = ssPostInstall) and WizardIsTaskSelected('addtopath') then
    AddToUserPath(ExpandConstant('{app}\tools'));
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromUserPath(ExpandConstant('{app}\tools'));
end;
