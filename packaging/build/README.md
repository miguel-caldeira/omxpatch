# Compilar os instaladores nos SO de origem

Cada instalador pode ser compilado **no sistema operativo para o qual se destina** (ferramentas nativas, wheels nativos, `.deb`/`.pkg`/`.exe` verdadeiros).
`packaging/build_installers.sh` continua a fazer a compilação cruzada (tudo a partir de Linux: `.tar.gz` e `.zip`).

| SO de origem | Comando | Produz | Requer |
|---|---|---|---|
| **Linux** (Ubuntu 24.04 recomendado) | `bash packaging/build/linux/build.sh` | `omxpatch-ubuntu-<v>.tar.gz`, `omxpatch-server_<v>_all.deb`, `omxpatch-agent_<v>_all.deb`, `omxpatch-agent-<v>-1.noarch.rpm`, agente e kit `.zip`, `SHA256SUMS` | bash, python3+pip, tar, `dpkg-deb`; `rpmbuild` (opcional, para o `.rpm`) |
| **Windows** (10/11, Server 2019+) | `powershell -ExecutionPolicy Bypass -File packaging\build\windows\build.ps1` | `omxpatch-windows-<v>.zip` e `…-setup-<v>.exe`, `omxpatch-windows2012r2-<v>.zip` e `…-setup-<v>.exe`, `omxpatch-agent-windows-<v>.zip` e `…-setup-<v>.exe`, kit, `SHA256SUMS.windows` | Python 3.9+ no PATH; Inno Setup 6 (`choco install innosetup -y`) para os `.exe`; acesso a python.org e PyPI |
| **macOS** | `bash packaging/build/macos/build.sh` | `omxpatch-agent-<v>.pkg` (+ `.sha256`) | ferramentas de linha de comandos (`xcode-select --install`), python3 |

Variáveis úteis: `DIST=<pasta>` (saída), `PYTHON=<python>`, `PYTHON_WIN_EXE`/`-Python312Exe`/`-Python311Exe` (instaladores do Python locais, para compilar sem acesso a python.org), `MACOS_INSTALLER_SIGN` e `MACOS_NOTARY_PROFILE` (assinatura e notarização do `.pkg`).

## Em CI (GitHub Actions)
`.github/workflows/installers.yml` compila **cada instalador no seu SO** (runners ubuntu-24.04, windows-latest, macos-latest), testa-os (instalar o agente `.deb`/`.pkg`/`.exe`, extrair os instaladores do servidor), junta tudo com `SHA256SUMS` e:
- **Actions → installers → Run workflow**: indique `release` (p.ex. `v1.34.20261115`) para criar/atualizar uma Release em rascunho com todos os ficheiros (cria o tag se não existir) e/ou marque `commit_to_repo` para guardar os instaladores compilados em `releases/<versão>/`;
- um tag `v*` empurrado para o GitHub dispara o mesmo.

## O que cada instalador faz
- **Servidor Linux (`.deb`/`.tar.gz`)**: instala/atualiza o centro de comando (`install.sh`/`update.sh`); `OMXPATCH_SKIP_INSTALL=1` só copia os ficheiros.
- **Servidor Windows (`…-setup-….exe`)**: extrai o pacote para `C:\ProgramData\OMXPatch\installer\<v>` e corre `Install-OMXPatch.ps1` numa janela visível (mostra a palavra-passe inicial). Opções: `/NORUN` (só extrair), `/HOSTNAME=… /AGENTHOSTNAME=… /SERVERIP=…`.
- **Agente**: `.deb`, `.rpm`, `.pkg` e `.exe` instalam os ficheiros e, se existir o ficheiro de inscrição (`/etc/omxpatch-agent/enroll.env`, `/Library/Application Support/OMXPatchAgent/enroll.env`, `C:\ProgramData\OMXPatchAgent\enroll.env` — ideal para MDM/GPO), inscrevem o agente e instalam o serviço. O `.exe` aceita também `/SERVER=… /TOKEN=… /PIN=…` e `/VERYSILENT`.
