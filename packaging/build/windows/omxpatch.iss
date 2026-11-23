; OMXPatch - instalador Windows (Inno Setup 6). Construido por packaging/build/windows/build.ps1
; /D defines: AppVer, Mode (server|agent), Src (pasta do pacote), Out (pasta de saida), OutName
#ifndef Mode
  #define Mode "server"
#endif
#if Mode == "server"
  #define AppTitle "OMXPatch - centro de comando"
  #define Script "Install-OMXPatch.ps1"
#else
  #define AppTitle "OMXPatch - agente"
  #define Script "Install-OMXPatchAgent.ps1"
#endif
[Setup]
AppId=OMXPatch-{#Mode}
AppName={#AppTitle}
AppVersion={#AppVer}
AppPublisher=OMXPatch
DefaultDirName={commonappdata}\OMXPatch\installer\{#AppVer}
DisableDirPage=yes
DisableProgramGroupPage=yes
Uninstallable=no
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#Out}
OutputBaseFilename={#OutName}
Compression=lzma2/fast
SolidCompression=no
WizardStyle=modern

[Languages]
Name: "en"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "{#Src}\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs ignoreversion

[Run]
; a instalacao corre numa janela visivel (mostra a palavra-passe inicial do super-administrador); /NORUN so copia os ficheiros
#if Mode == "server"
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\{#Script}"" -Pause{code:ServerArgs}"; WorkingDir: "{app}"; Flags: waituntilterminated; Check: ShouldRun; StatusMsg: "A instalar o OMXPatch..."
#else
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\{#Script}"" -Pause{code:AgentArgs}"; WorkingDir: "{app}"; Flags: waituntilterminated; Check: ShouldRun; StatusMsg: "A instalar o agente..."
#endif

[Code]
function CmdLineParamExists(const Name: string): Boolean;
var I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do if CompareText(ParamStr(I), Name) = 0 then Result := True;
end;

function ShouldRun: Boolean;
begin
  Result := not CmdLineParamExists('/NORUN');
end;

function GetParam(const Name: string): string;
var I: Integer; P: string;
begin
  Result := '';
  for I := 1 to ParamCount do begin
    P := ParamStr(I);
    if CompareText(Copy(P, 1, Length(Name) + 1), Name + '=') = 0 then Result := Copy(P, Length(Name) + 2, MaxInt);
  end;
end;

function ServerArgs(Param: string): string;
begin
  Result := '';
  if GetParam('/HOSTNAME') <> '' then Result := Result + ' -Hostname "' + GetParam('/HOSTNAME') + '"';
  if GetParam('/AGENTHOSTNAME') <> '' then Result := Result + ' -AgentHostname "' + GetParam('/AGENTHOSTNAME') + '"';
  if GetParam('/SERVERIP') <> '' then Result := Result + ' -ServerIp "' + GetParam('/SERVERIP') + '"';
end;

function AgentArgs(Param: string): string;
begin
  Result := '';
  if GetParam('/SERVER') <> '' then Result := Result + ' -Server "' + GetParam('/SERVER') + '"';
  if GetParam('/TOKEN') <> '' then Result := Result + ' -Token "' + GetParam('/TOKEN') + '"';
  if GetParam('/PIN') <> '' then Result := Result + ' -Pin "' + GetParam('/PIN') + '"';
  if CmdLineParamExists('/ALLOWEXEC') then Result := Result + ' -AllowExec';
end;
