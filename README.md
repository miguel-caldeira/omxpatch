# OMXPatch

Centro de comando de **gestão de patches e remediação contínua**, irmão do **OMXVuln** e do **OMXGRC**. Passa de
*Ativo → Vulnerabilidade → Patch* para:

```
Ativo → Exposição → Risco → Mitigação → Patch → Validação → Monitorização contínua
```

Usa a mesma base e o mesmo modo de trabalho das outras ferramentas: **Python / Flask / SQLAlchemy**, multitenant com
perfis (Administrador, Operador, Auditor, Super-administrador), MFA TOTP, auditoria, licenciamento por organização,
HTTPS autoassinado gerido, API REST com tokens, worker embebido ou separado, configuração por TOML/variáveis de
ambiente, CSP estrita e o mesmo tema. O trabalho operacional é articulado por **Ansible** (instalação, agentes, modo sem
agente, mitigação, descoberta).

| Componente | O que é |
|---|---|
| **Centro de comando** (`omxpatch/`) | Interface web gráfica + API + worker. Contém o **repositório de patches** (identificados, descarregados, aprovados), as campanhas, os anéis, os controlos compensatórios, a IA e os painéis. |
| **Cliente / agente** (`omxpatch_agent/`) | Windows, Linux e macOS. Só liga *para fora* (HTTPS), regista-se com um token, envia inventário e executa o que *puxa*: patches, validações, simulações seguras, firewall local, Wake-on-LAN. |
| **Ansible** (`ansible/`) | Instala o servidor e os agentes; no **modo sem agente** o próprio centro de comando corre inventário, patches, validação e mitigação por SSH/WinRM. |

> ## Versão atual: **1.13.20261108**
> **Instaladores** (em [`releases/1.13.20261108/`](releases/1.13.20261108/), com `SHA256SUMS`):
> [Ubuntu/Debian](releases/1.13.20261108/omxpatch-ubuntu-1.13.20261108.tar.gz) ·
> [Windows](releases/1.13.20261108/omxpatch-windows-1.13.20261108.zip) ·
> [Windows Server 2012 R2](releases/1.13.20261108/omxpatch-windows2012r2-1.13.20261108.zip) ·
> [Agente](releases/1.13.20261108/omxpatch-agent-1.13.20261108.zip) ·
> [Kit de validação Windows/macOS](releases/1.13.20261108/omxpatch-validation-kit-1.13.20261108.zip)
>
> **Manuais:** [Utilização](docs/MANUAL-UTILIZACAO.md) ([PDF](releases/1.13.20261108/docs/MANUAL-UTILIZACAO-1.13.20261108.pdf)) ·
> [Administração](docs/MANUAL-ADMINISTRACAO.md) ([PDF](releases/1.13.20261108/docs/MANUAL-ADMINISTRACAO-1.13.20261108.pdf)) ·
> [Referência técnica](docs/REFERENCIA.md) · [Histórico de versões](CHANGELOG.md)

---

## Módulos (arquitetura funcional)

| # | Módulo | Onde |
|---|---|---|
| 1 | **Asset Discovery & Inventory** — CMDB integrada, agente e sem agente, cloud, contentores, Kubernetes, IoT/OT, Shadow IT; AD, Entra ID, VMware, Hyper-V, AWS, Azure, GCP | `engine/inventory.py`, `connectors/discovery.py`, agente `collectors/` |
| 2 | **Vulnerability Intelligence** — NVD, CISA KEV, EPSS, MITRE, feeds de ameaças, avisos de fabricantes; correlação ativo → software → versão → CVE → exploração → patch | `engine/intel.py`, `engine/correlate.py` |
| 3 | **Exposure Management multi-vendor** — Defender, SentinelOne, CrowdStrike, Tenable, Qualys, Rapid7, Wiz, Prisma, Check Point, Palo Alto, Fortinet, Zscaler; veredicto «vulnerável + exploração ativa + firewall não bloqueia + EDR não deteta + sem patch ⇒ risco crítico» | `connectors/signals.py`, `engine/risk.py` |
| 4 | **Dynamic Risk Score** 0–100 (CVSS, EPSS, KEV, criticidade, Internet, valor de negócio, evidência de exploit) → Baixo / Médio / Alto / Crítico / Emergência; risco **residual** com controlos compensatórios | `engine/risk.py` |
| 5 | **Patch Intelligence** — taxa de sucesso (comunidade + telemetria da organização), incidentes do fabricante, problemas reportados, histórico de rollback, impacto operacional → Aplicar / Cautela / Não aplicar | `engine/patches.py` |
| 6 | **Automated Patch Management** — Windows/Linux/macOS e aplicações (Adobe, Chrome, Edge, Firefox, Java, SAP GUI, Zoom, Teams, Office, Acrobat, OpenSSL…) por winget/apt/dnf/zypper/brew/MSI/EXE/PKG; agendamento, janelas de manutenção, **Wake-on-LAN**, deployment remoto, **controlo de largura de banda** | `engine/deploy.py`, agente `patchers/` |
| 7 | **Smart Test Rings** — Ring 0 Laboratório → Ring 4 Produção; promoção automática por taxa de sucesso, crash rate, UX e telemetria, com período de observação | `engine/rings.py` |
| 8 | **Compensating Controls** — Firewall (IOC, porta, país), EDR (deteção/bloqueio), SIEM (regra/correlação), IAM (desativar conta/MFA), WAF (virtual patch), com artefacto gerado | `engine/controls.py` |
| 9 | **AI Remediation Engine** — «Como reduzir o risco para menos de 20 pontos?» → plano de esforço mínimo e redução prevista (ex.: 92 → 14) | `engine/advisor.py` |
| 10 | **Closed Loop Validation** — patch instalado, serviço reiniciado, CVE desapareceu, exposição eliminada, compliance atingido | `engine/validation.py` |
| 11 | **Security Operations Integration** — SIEM (Sentinel, Splunk, QRadar, Elastic), SOAR (XSOAR, Sentinel Automation, Tines), ITSM (ServiceNow, Jira, Freshservice), EDR (Defender XDR, SentinelOne, CrowdStrike) | `connectors/outbound.py` |
| 12 | **Compliance & Governance** — NIS2, ISO 27001 (A.8 / A.8.8), DORA, PCI-DSS Req. 6, CIS Controlo 7 | `engine/compliance.py` |
| 13 | **Executive Dashboard (CISO)** — ativos, CVE, expostos, MTTP, MTTR, % compliance, KEV, top ativos exploráveis | `engine/executive.py`, `/` |
| 14 | **Threat Exposure Simulation (BAS)** — ransomware, movimento lateral, roubo de credenciais, cadeias de exploração, antes/depois da correção | `engine/simulation.py`, agente `bas.py` |
| 15 | **Autonomous Remediation** — novo CVE → … → fecho, CMDB e reporte executivo (modos *aconselhar* e *autónomo*) | `engine/autonomous.py` |

### Atualizações no Windows: origens suportadas e simulação prévia

O agente **sonda** o que realmente funciona em cada equipamento (normalmente como SYSTEM) e envia-o no inventário; o servidor só encaminha
um patch para um ativo cujo instalador seja suportado (página **Origens e simulações**).

| Origem | Instalador | Notas |
|---|---|---|
| Windows Update / WSUS / Microsoft Update | `wua` (por KB) | API WUA; respeita a política WSUS do equipamento |
| winget | `winget` | no contexto SYSTEM o agente localiza o `winget.exe` em *WindowsApps*; alguns pacotes só instalam por utilizador |
| Chocolatey | `choco` | só se estiver instalado |
| MSI / patch MSI | `msi`, `msp` | ficheiro do repositório (SHA-256); códigos 0 / 3010 / 1641 / 1638 tratados |
| EXE silencioso | `exe` | exige os argumentos do fabricante (`silent_args`, validados) |
| MSU / CAB | `msu` (wusa), `cab` (DISM) | pacotes do Microsoft Update Catalog |
| Office / Microsoft 365 | `office_c2r` | `OfficeC2RClient.exe /update` |

Linux (apt, dnf/yum, zypper) e macOS (softwareupdate, brew, pkg) seguem o mesmo modelo. O catálogo de aplicações habituais (Chrome, Edge, Firefox,
Java, Zoom, Teams, Acrobat, OpenSSL, Office, SAP GUI) é um ponto de partida: confirme os identificadores no seu ambiente.

**Simulação prévia (pré-voo)** — em *Patches → Simulação prévia* (ou `POST /api/v1/patches/<id>/simulate`) o agente verifica, **sem instalar**, o que
aconteceria: aplicabilidade (WUA: pesquisa sem descarregar; `winget list --upgrade-available`; `choco outdated`; `apt-get -s`; `dnf check-update`;
`zypper --dry-run`; `softwareupdate -l`), versões antes/depois, outros pacotes afetados e remoções, assinatura Authenticode/pkg, propriedades do MSI,
privilégios, espaço em disco, reinício pendente e previsto, aplicação em utilização e saúde do sistema. O instalador fica em *staging* (SHA-256
verificado) e a instalação real reutiliza-o. Resultado por ativo: **pronto**, **com avisos**, **bloqueado**, **nada a instalar** ou **erro**.
Uma campanha com *Exigir simulação prévia* (sempre ativa no modo autónomo) só instala nos ativos aprovados; os bloqueados e os já atualizados ficam
ignorados com o motivo, e um anel em que todos ficam bloqueados fica em pausa.

### Risco dinâmico (Módulo 4)

| Fator | Máx. | Regra |
|---|---|---|
| CVSS | 25 | CVSS ×2,5 |
| EPSS | 15 | <1 % = 2 · <10 % = 6 · <50 % = 11 · ≥50 % = 15 |
| KEV | 15 | CISA KEV = 12; +3 se usada em ransomware |
| Criticidade do ativo | 12 | crítica 12 · alta 8 · média 4 · baixa 0 |
| Exposição à Internet | 10 | IP público / SaaS / definido no ativo |
| Valor de negócio | 8 | 0–100 do ativo |
| Evidência de exploit | 15 | exploração observada no ambiente = 15; senão maturidade (weaponized 10, funcional 7, PoC 4) + malware |

Baixo < 25 ≤ Médio < 50 ≤ Alto < 70 ≤ Crítico < 85 ≤ Emergência. O risco de um **ativo** é a probabilidade combinada das
suas exposições, `1 − Π(1 − sᵢ/100)`. O prazo (SLA) vem da categoria e é configurável por organização.

### Fluxo autónomo (Módulo 15)

```
Novo CVE → Descoberta → Avaliação de risco → Mapeamento dos ativos → Procura de patch → Teste (Ring 0)
        → Ring deployment → Validação → Fecho automático → Atualização da CMDB → Reporte executivo
```

Sem patch, o fluxo propõe (e, em modo autónomo, aplica) controlos compensatórios e aguarda o patch. **Voltam sempre a um
humano**: Patch Intelligence em «não aplicar», critérios de anel falhados, validações falhadas.

---

## Instalação

### Servidor (Ansible, recomendado)

```bash
cd ansible
ansible-galaxy collection install -r requirements.yml
ansible-playbook -i inventory.example.ini site.yml -e omxpatch_server_name=omxpatch.exemplo.pt \
    -e omxpatch_pip_spec=omxpatch            # nome num índice interno, ficheiro .whl ou caminho
```

Instala venv, `omxpatch.toml`, serviços systemd (web + worker) e, opcionalmente, NGINX (`-e omxpatch_nginx=true`).
A password inicial do super-administrador (`admin@omxpatch.local`) é mostrada no fim e fica em `initial_admin.txt`.

### Instaladores (pacotes prontos)

`packaging/build_installers.sh` gera em `dist/` (também no CI e nas *releases* do GitHub):

| Pacote | Conteúdo |
|---|---|
| `omxpatch-ubuntu-<versão>.tar.gz` | centro de comando para Ubuntu 24.04/26.04 ou Debian: `sudo ./install.sh [--hostname … --agent-hostname … --server-ip …]`; ambiente virtual com *wheelhouse* offline, serviços systemd (web + worker), ufw 4434/4444, certificados e password inicial |
| `omxpatch-windows-<versão>.zip` | centro de comando para Windows Server/10/11: `Instalar.cmd` ou `Install-OMXPatch.ps1`; instala o Python se faltar, tarefas agendadas SYSTEM, regras de firewall, certificados |
| `omxpatch-windows2012r2-<versão>.zip` | centro de comando para **Windows Server 2012 R2**: Python 3.11 (o 3.12 já não o suporta), verificações prévias (PowerShell 4, .NET 4.5, KB2999226), TLS 1.2 no .NET; os agentes gerados na consola usam o Python 3.8.10 em Windows < 10 |
| `omxpatch-agent-<versão>.zip` | agente (só biblioteca padrão) para instalação manual/offline; o normal é gerar os scripts de auto-instalação na consola |

Cada pacote traz `LEIA-ME.txt`, atualiza mantendo dados e configuração, e tem desinstalador. Verificação: `SHA256SUMS`.
O instalador Ubuntu foi executado de verdade (instalação, certificados, arranque nas duas portas, remoção); o do Windows **não** foi executado num Windows.

### A partir do código-fonte

```bash
pip install -r requirements.txt            # Python ≥ 3.9 (recomendado ≥ 3.11)
python -m omxpatch serve                   # consola https://…:4434 e agentes https://…:4444; dados em ~/.local/share/omxpatch
python -m omxpatch create-tenant --name "Empresa" --admin-email admin@empresa.pt
```

Comandos: `serve`, `worker`, `tls info|generate`, `init`, `create-tenant`, `reset-admin`, `initial-password`, `check`,
`intel-sync`, `correlate`, `import-intel`, `agent-token`, `ansible-vars`. Configuração: ver `omxpatch.toml.example`.

### Portas e certificados

| Porta | Acesso | Nome / certificado (autoassinado, 2 anos) | Serve |
|---|---|---|---|
| **4434** | Gestão (consola gráfica) | `omxpatch.oramix.local` | interface web, API REST, tokens |
| **4444** | Agentes → consola | `omxpatchcli.oramix.local` | só `/agent/v1/*` e `/healthz` |

São dois certificados independentes (gerados no primeiro arranque e renovados 30 dias antes de expirar; `omxpatch tls info`
mostra nomes, validade e SHA-256). A consola **não** serve `/agent/` e a porta dos agentes **não** serve a interface nem a API,
pelo que o ambiente gráfico nunca fica exposto aos postos clientes. Os nomes têm de resolver (DNS, ou `[agents] server_ip` para os
scripts o acrescentarem ao ficheiro *hosts* dos postos). Abra no firewall as duas portas. Certificados próprios: `[server] tls_cert/tls_key`
e `[agents] tls_cert/tls_key`.

### Organizações (tenants) e agentes

Cada agente reporta a **uma única organização**: a do token de registo com que foi instalado. Um equipamento (identificado por
`machine-id` / `IOPlatformUUID` / `MachineGuid`) já registado numa organização é recusado (HTTP 409) por qualquer outra até o agente ser
revogado/eliminado na primeira. Reinstalar na mesma organização substitui a chave anterior. Cada organização tem a sua identidade visual
(logótipo e cores em *Organização → Identidade visual*), como no OMXVuln; a marca é «**OMX**» a laranja e «Patch» a branco.

### Agentes — Windows, Linux, macOS (instalação remota por script)

Em **Agentes → Scripts de auto-instalação** (organização ativa) escolha o sistema operativo, o anel e a validade e descarregue o script:
`omxpatch-install-<organização>-windows.ps1` / `-linux.sh` / `-macos.sh`. O script leva o token da organização, o URL do servidor de
agentes e a impressão digital do certificado `omxpatchcli.oramix.local`; **não precisa de pip nem de Internet** (só de Python 3, que instala
se faltar): descarrega o agente por TLS com *pinning*, verifica o SHA-256, regista o equipamento e instala o serviço
(systemd / LaunchDaemon / tarefa agendada SYSTEM). O agente usa apenas a biblioteca padrão do Python. Há scripts de remoção.

```bash
# Linux / macOS (local ou por SSH)
sudo sh omxpatch-install-empresa-linux.sh          # ou:  ssh root@posto 'sh -s' < omxpatch-install-empresa-linux.sh
# Windows (PowerShell como administrador, GPO, Intune, SCCM ou Invoke-Command -FilePath …)
.\omxpatch-install-empresa-windows.ps1
# Em massa com Ansible (SSH/WinRM)
ansible-playbook -i inventario.ini ansible/install_agent_script.yml -e omxpatch_script=omxpatch-install-empresa-linux.sh
```

Alternativas: `ansible/deploy_agent.yml` (role com pip) ou instalação manual `omxpatch-agent enroll --server https://omxpatchcli.oramix.local:4444 --token … --pin-sha256 …`.
Gestão: lista de agentes (organização, versão, último contacto, online/offline), revogar e eliminar.

**Sem agente:** marque o ativo como «Sem agente (Ansible)»; o worker executa `inventory_*`, `patch_*`, `validate_*` e `mitigate_firewall_*` por SSH/WinRM
(`pip install 'omxpatch[ansible]'`).

Segurança do agente: só liga para fora; chave própria guardada com hash no servidor e revogável; *pinning* do certificado; pacotes só
descarregáveis pelo ativo a quem a tarefa pertence e verificados por **SHA-256**; nomes de pacotes, KB, portas e IP validados (sem shell);
scripts gerados só com valores validados (sem injeção) e entregues com `Cache-Control: no-store`.

---

## Integração com o OMXVuln e o OMXGRC

**OMXVuln** (API `/api/v1`, token Bearer; `X-Tenant-ID` para super-administradores) — em *Integrações → OMXVuln* ou `[omxvuln]`:

- **entrada — ativos:** `GET /assets` (ou `/targets`; opção `assets_path`) → CMDB do OMXPatch (nome, IP, FQDN, SO, criticidade,
  etiquetas, responsável, software). Os ativos já geridos por agente só são completados (campos vazios), nunca sobrescritos.
- **entrada — vulnerabilidades:** `GET /findings` → exposições (CVE, software, versão instalada, versão corrigida, KEV/EPSS; opção
  `min_severity`); o OMXVuln é a fonte de verdade da deteção.
- **simular antes de importar:** *Integrações → OMXVuln → Importar ativos e vulnerabilidades* mostra o que seria criado (nada é
  gravado) e só importa após «OK». API: `POST /api/v1/sync/omxvuln {"what":"assets|findings|both","dry_run":true}`. O worker repete
  a importação de `OMXVULN_SYNC_MINUTES` em `OMXVULN_SYNC_MINUTES` minutos (ativos incluídos, salvo `sync_assets=false`). Uma deteção que desaparece do OMXVuln passa a *remediada* e é validada.
- **saída:** após a validação em ciclo fechado, `POST /findings/<id>/status` (*remediada*) e `POST /scans` ao alvo do ativo, para o
  OMXVuln fechar a deteção com verificação independente.

**OMXGRC** — em *Integrações → OMXGRC* ou `[omxgrc]`:

- **push:** métricas dos cinco referenciais (`POST <metrics_path>`) e uma **evidência** por remediação validada (`POST <evidence_path>`);
- **pull:** `GET /api/v1/grc/controls` e `GET /api/v1/grc/evidence` neste servidor.

> Os caminhos do OMXGRC são configuráveis porque o contrato exato da API do OMXGRC não foi consultado; ajuste-os se diferirem.
> O mesmo vale para o OMXVuln: o código do OMXVuln não estava acessível, por isso os nomes dos campos de `/assets` e `/findings` seguem um
> mapeamento tolerante (vários *aliases*) testado só com respostas simuladas; valide com *Simular importação* numa instância real.

## API REST

Token em **Perfil → Tokens de API**; `Authorization: Bearer omp_…`.

```bash
curl -H "Authorization: Bearer $T" https://omxpatch/api/v1/exposures?category=emergency
curl -H "Authorization: Bearer $T" -d '{"question":"Como reduzir o risco para menos de 20 pontos?","asset_id":3}' \
     -H "Content-Type: application/json" https://omxpatch/api/v1/advisor
curl -H "Authorization: Bearer $T" -X POST "https://omxpatch/api/v1/signals?vendor=paloalto" --data-binary @fw.csv -H "Content-Type: text/csv"
curl -H "Authorization: Bearer $T" -X POST https://omxpatch/api/v1/sync/omxvuln
```

`/me`, `/assets`, `/discover`, `/exposures`, `/correlate`, `/intel/<cve>`, `/patches`, `/patches/<id>/approve`, `/campaigns`,
`/signals`, `/controls`, `/advisor`, `/autonomous`, `/validations`, `/compliance`, `/executive`, `/sync/omxvuln`, `/sync/omxgrc`,
`/grc/controls`, `/grc/evidence`, `/enrollment-tokens`, `/practices`, `/plans`.

## Boas práticas e planos de operações

Além de instalar patches, o OMXPatch aplica **boas práticas de configuração** (menu *Operações e boas práticas*):

| Boa prática | nginx | Apache | IIS |
|---|---|---|---|
| TLS 1.2/1.3 apenas, cifras «intermediate» da Mozilla | `ssl_protocols`, `ssl_ciphers` | `SSLProtocol`, `SSLCipherSuite` | Schannel + .NET (exige reinício) |
| HSTS | `add_header` | `Header always set` | `customHeaders` |
| Ocultar a versão | `server_tokens off` | `ServerTokens Prod` | `removeServerHeader`, `X-Powered-By` |
| Cabeçalhos de segurança | sim | sim | sim |

**Fluxo obrigatório: simular → OK → executar.** Um *plano* junta ativos × operações (patches e/ou boas práticas):

1. **Simular** — o agente não altera nada e devolve verificações, as **ações** (com *diff* dos ficheiros/registo) e o resultado previsto
   (`pronto`, `avisos`, `bloqueado`, `nada a fazer`, `erro`).
2. **OK explícito** — só itens simulados (há menos de 24 h) e sem bloqueio podem ser aprovados; é preciso marcar a caixa «OK»
   (e aceitar os avisos, se existirem). Sem OK, nenhuma tarefa de execução é criada. Na API: `{"ok": true}`.
3. **Executar** — apenas os itens aprovados, respeitando hora de início e janelas de manutenção.

Cada plano pode ser visto **por operação** (a atualização/prática a aplicar, em vários ativos) ou **por ativo** (várias operações num ativo).
A aplicação de boas práticas faz cópia de segurança, `nginx -t`/`apachectl configtest`, recarga, verificação real dos protocolos TLS
(handshakes TLS 1.0/1.1/1.2/1.3) e **reversão automática** se algo falhar; itens concluídos podem ser revertidos manualmente.

API: `GET /api/v1/practices`, `GET|POST /api/v1/plans`, `POST /api/v1/plans/<id>/simulate|approve|execute`.

## Cenário de teste em Windows e macOS

O que só foi testado com saídas simuladas (WUA, winget, Chocolatey, `softwareupdate`, brew, contexto, firewall, endurecimento, isolamento) valida-se em sistemas reais com `python -m omxpatch_agent validate`:

- **`--level read` (omissão): só leitura** — autoteste, inventário, origens utilizáveis, descoberta de atualizações (sem instalar), contexto do ativo, servidores web, planos de boas práticas e ferramentas de firewall;
- **`--level lab --yes-lab`: + alterações reversíveis** (regra de firewall de teste e endurecimento do SO aplicados e revertidos) — só em VM de laboratório;
- **`--with-isolation --server https://IP:4444 --pin …`**: testa o isolamento real (5 min, só a consola acessível) e a ligação **por IP + impressão digital**.
Gera `report-*.md/json` (nome do equipamento e IP ocultados por omissão).

**Três vias:** (1) **CI** (`.github/workflows/ci.yml`): o job `real-os-validation` corre o nível `lab` em *runners* Windows e macOS **reais e descartáveis** do GitHub e publica o relatório como artefacto; o `agent-compat` corre o `selftest` de Python 3.8 a 3.13 nesses sistemas; (2) **kit** `omxpatch-validation-kit-<versão>.zip` (agente + `validate-windows.ps1` + `validate-macos.sh` + `CHECKLIST-LAB.md` com os casos manuais: registo por IP, descarga proativa, simulação/instalação, IIS TLS, SMBv1/NLA, isolamento com plano B, rotação do certificado, tarefas assinadas, atualização do agente); (3) comando diretamente num equipamento.

## Fluxo Descoberta → Simulação → Remediação (agente leve, inteligência no servidor)

**Agente leve:** recolhe telemetria só de leitura (inventário, atualizações instaláveis e o *contexto* do ativo: processos, quem escuta em que porta e a partir de onde, serviços, estado da firewall, administradores, SSH/RDP/SMB/UAC, SELinux/Defender) com prioridade baixa e orçamento de tempo (medido: ~25 ms em Linux), e executa as ordens aprovadas. **Todo o processamento pesado** — correlação, simulação, prioridade — corre na consola. Tudo viaja por TLS com o certificado fixado (impressão digital).

**Simulação de exposição (servidor, sem impacto no ativo):** para cada vulnerabilidade cruza a inteligência (KEV, maturidade do exploit, EPSS, vetor CVSS) com o contexto real e constrói o caminho de ataque em passos — componente em execução? escuta acessível pela rede (não só em loopback)? firewall do ativo permite? exposto à Internet? sem controlos eficazes? — e conclui `confirmada`, `provável`, `improvável`, `inalcançável` ou `sem contexto` (cada passo é ok/falha/desconhecido, com confiança). Reduz falsos positivos: `inalcançável` (p.ex. MySQL só em loopback, serviço parado, firewall a bloquear) baixa a prioridade. Bibliotecas sem processo próprio ficam «desconhecido», nunca «inalcançável».

**Prioridade por impacto, não só CVSS:** perda esperada = P(exploração) × impacto, com P do EPSS/KEV × peso da simulação (1,0 … 0,03) × controlos, e impacto = custo/hora do ativo (próprio ou por criticidade) × horas de paragem × fator de valor de negócio. Os valores `IMPACT_*` são **pressupostos configuráveis** (Sistema → Configuração), não medições. O Centro de comando e *Exposição e risco* ordenam por perda esperada (`/exposures?sort=loss`, `/api/v1/priority`).

**Remediação:** patches e boas práticas pelos planos (simular → OK → executar); **configurações incorretas** detetadas na postura do ativo (SSH com root/palavra-passe vazia, SMBv1, RDP sem NLA, firewall desativada, base de dados aberta) vêm com a ação recomendada e duas novas boas práticas — `ssh_hardening` (com salvaguarda contra bloqueio: só desativa a palavra-passe se existirem chaves autorizadas; `sshd -t`; reversão automática) e `windows_hardening` (SMBv1/NLA, com reposição); **isolamento preventivo** do ativo (controlo `isolate_host`, com aprovação): o agente corta tudo menos a ligação à consola (nftables/iptables, Windows Firewall, pf), testa a consola depois de isolar e desfaz sozinho se a perder, tem validade máxima de 24 h e repõe o estado anterior.

**Linha de base (gold images):** cada remediação bem-sucedida entra em *Linha de base* (patch → versão mínima, boa prática → parâmetros); mede o desvio dos ativos e exporta para Ansible, shell (com verificação das versões mínimas), Packer ou JSON, para que as imagens novas não nasçam com a mesma vulnerabilidade.

**ITSM (ServiceNow, Jira, Freshservice) — desativado por omissão.** Sem a opção `change_management = true` na integração, **todo o ciclo de aprovação é feito diretamente pela solução**. Ativada: o plano (ou o controlo) pede uma *change* no ITSM com as ações simuladas; a execução fica **bloqueada** até o ITSM a aprovar (ServiceNow: `approval = approved` e estado Scheduled/Implement); falha de comunicação ou rejeição nunca aprovam; no fim o resultado é escrito na change. O OK na solução continua a ser exigido. *Testado só com respostas simuladas da API do ServiceNow/Jira/Freshservice, não contra instâncias reais; os estados e campos devem ser validados na sua instância.*

## Descoberta de atualizações, descarga proativa e remediação

*Atualizações* mostra, por ativo, **o que pode ser instalado**, com a garantia de que a informação chega à consola:

1. **Descoberta (agente):** a cada `UPDATES_SCAN_HOURS` (6 h) e a pedido («Descobrir agora»), o agente varre as origens do SO sem instalar nada: **apt** (`apt-get -s dist-upgrade`, URL e SHA-256 do índice assinado), **dnf/yum** (`check-update` + `updateinfo`), **zypper**, **Windows Update/WSUS** (WUA: KB, severidade, CVE, tamanho, reinício), **winget** (URL e SHA-256 do manifesto), **Chocolatey**, **softwareupdate** e **brew**. O relatório fica em disco até a consola **confirmar a receção** (*store-and-forward*); a consola regista cada receção em «Histórico de descobertas» e é idempotente por `scan_id`.
2. **Consola:** cada atualização fica em `AvailableUpdate`, ligada a um `Patch` do repositório (partilhado entre ativos) e às exposições do ativo (por CVE, ou por pacote + versão corrigida). Uma origem com varrimento completo que deixa de listar uma atualização marca-a como instalada.
3. **Descarga proativa:** o worker descarrega para o repositório os ficheiros com URL e **SHA-256 anunciado** pela origem (SSRF validado em cada redirecionamento, limite de tamanho, hash verificado antes de gravar; adulterado = rejeitado). Sem hash ou sem URL (p.ex. dnf, Windows Update, macOS) a atualização usa o gestor/serviço do próprio equipamento («usam a origem do SO»). `http` só com SHA-256.
4. **Simulação e remediação:** «Simular as selecionadas» cria um plano com os pares ativo × patch exatos e pede a simulação; o agente recebe o ficheiro **do servidor** (SHA-256 verificado) e simula com `apt-get -s` do ficheiro; instalar exige aprovar o patch e dar OK no plano.

**Limites assumidos:** só apt (com `.deb` do servidor) e winget (MSI/EXE do manifesto) têm descarga fiável hoje; Windows Update só descarrega se o WUA expuser o URL, e dnf/zypper/macOS não trazem hash verificável. O `apt-get install ./ficheiro.deb` resolve dependências nos repositórios do SO: não é um espelho offline completo. Verificado: apt real (descoberta, envio, descarga de `archive.ubuntu.com` com SHA-256, simulação do `.deb`); os restantes analisadores com saídas representativas, não em sistemas reais.

## Centro de comando (dashboard)

A página inicial consolida a solução num só ecrã, com gráficos SVG (sem scripts nem estilos inline, compatível com a CSP):

- **Ações recomendadas** por prioridade (KEV sem simulação, operações a aguardar OK, SLA, servidores web sem TLS 1.2/1.3, agentes offline ou com Python antigo, validações falhadas…), cada uma com o seu botão;
- indicadores (exposições, ativos, agentes online, a aguardar OK, compliance, MTTP/MTTR, campanhas, validações), **exposição por risco** (anel), **funil de remediação** (exposição → patch → aprovado → simulado → OK → em execução → concluído) e **conformidade** (NIS2, ISO 27001, DORA, PCI-DSS, CIS);
- **remediação prioritária** por patch (e CVE sem patch, a mitigar), operações a aguardar OK, campanhas com progresso, boas práticas dos servidores web, frota por SO (agente/Ansible/sem gestão), saúde e integrações (licença, OMXVuln, OMXGRC; para o super-administrador também carga prevista, certificados, última cópia), atividade recente, tendência e ativos mais exploráveis.

**Simular e remediar com um clique:** «Simular» cria um plano de operações (por patch, por ativo, ou TLS 1.2/1.3 nos servidores em falta) e pede a simulação; «Remediar…» faz o mesmo e abre o plano. **Nada é aplicado sem o OK explícito** na página do plano; o auditor vê o painel mas não os botões. O painel executivo anterior continua em *Executivo* (`/executive`).

## Capacidade, configuração e reinício

*Sistema → Capacidade e carga* (super-administrador; CLI: `omxpatch capacity [--benchmark --agents 50 --seconds 10]`):

- estado da máquina (CPU, memória, disco, base de dados), agentes online, fila de tarefas, latência p50/p95/p99 por grupo de rotas e ciclo do worker;
- **modelo de capacidade:** contactos/s previstos (agentes ÷ intervalo, ×3 em pico) contra a capacidade medida (com 40 % de folga) ou, sem teste, uma estimativa conservadora; indica o máximo de agentes e recomendações (PostgreSQL, intervalo de contacto, worker separado, disco, memória…);
- **teste de carga** (com «OK»): agentes simulados `loadtest-N` contactam a pilha real (autenticação + BD) e são removidos no fim. Mede **um processo web, sem rede nem TLS**: é um limite superior; confirme com um piloto real.

*Sistema → Configuração e reinício:* alterar parâmetros (intervalos, threads, segurança…) em dois passos (pré-visualizar → «OK»), com validação cruzada (nunca grava uma combinação que não arranca), cópia de segurança e reposição. As alterações ficam em `omxpatch.overrides.toml`; um ficheiro inválido é ignorado no arranque. O **reinício** valida a configuração antes; com supervisor (systemd; ciclo dos serviços Windows do instalador) o processo termina e é rearrancado, sem supervisor relança-se a si próprio. O worker separado termina no ciclo seguinte.

## Agentes: Python do sistema, sem Ansible

O agente faz tudo sozinho em Python (inventário, patching, simulação, boas práticas, BAS, controlos, validação), por isso não depende do Ansible nem de um Python em particular: **3.8 – 3.13 testados** (3.7 por análise estática). `python -m omxpatch_agent selftest` valida cada capacidade no equipamento; o interpretador (versão, OpenSSL, nível `ok`/`legacy`, limitações) é reportado ao servidor no inventário. Os scripts de instalação escolhem o Python conforme o SO (Windows < 10 / Server 2012 R2: 3.8.10).

**Só IP + thumbprint:** com `AGENT_ADDRESS_MODE=ip` e `AGENT_SERVER_IP`, os agentes falam com `https://<IP>:4444` sem DNS, ficheiro hosts nem CA: confiam apenas na impressão digital do certificado (SHA-256, ou o *thumbprint* SHA-1 do Windows) que o script traz. Por IP sem impressão digital o agente recusa ligar. `AGENT_SERVER_URLS` publica endereços alternativos (*failover*) aos agentes. O certificado dos agentes **não é regenerado** quando o IP do servidor muda, para o thumbprint se manter.

## Endurecimento e operação

- **Rotação do thumbprint:** quando faltam menos de 60 dias para o certificado dos agentes expirar, o worker prepara o seguinte e a consola publica os **dois** thumbprints no contacto; os agentes só os adotam se contiverem o que acabaram de validar (continuidade). Passados 7 dias o seguinte substitui o atual no arranque seguinte. Agentes fixados ignoram a validade, por isso não há corte. Um agente offline durante todo o período precisa de ser reinstalado.
- **Tarefas e pacote assinados (Ed25519):** cada tarefa vai com `iat` e assinatura, ligada ao agente; o agente (verificação em Python puro, sem dependências) recusa tarefas alteradas, de outro agente, sem assinatura ou com mais de 1 h. As chaves públicas são fixadas no registo e só se substituem por uma lista que contenha uma conhecida (`omxpatch signing show|rotate`). Protege contra alterações na base de dados, em proxies e por quem não tenha a chave privada (`<dados>/signing/task.key`); **não** protege contra quem controle o servidor inteiro.
- **Atualização automática dos agentes:** o agente descarrega o pacote anunciado, confere SHA-256 **e** assinatura, corre o `selftest` do código novo e só então troca a pasta (a anterior fica em `omxpatch_agent.prev`; reversão disponível) e reinicia-se. Não atualiza instalações em `site-packages` nem sem assinatura. Desligar: `AGENT_AUTO_UPDATE=false`.
- **Limitação de pedidos:** por IP no registo/pacote (`RATE_ENROLL_PER_MIN`), bloqueio de 30 s após `RATE_AUTH_FAIL_PER_MIN` tokens/chaves inválidos por IP, e `RATE_AGENT_PER_MIN` por agente. Em memória, por processo.
- **Versões fixas:** `requirements.lock` (uv, universal, com hashes) é o que o build dos instaladores e o CI usam (`pip --require-hashes`). Regenerar: `uv pip compile requirements.txt --universal --generate-hashes --python-version 3.9 -o requirements.lock`.
- **Migrações versionadas:** `omxpatch db status|upgrade`; cada migração corre uma vez, em transação (inclui DDL em SQLite), com cópia prévia da base. Para alterar/remover colunas acrescente uma entrada a `MIGRATIONS` em `migrations.py` (não é o Alembic: não há reversão automática).
- **Cópias e retenção:** `omxpatch backup [list]` / `omxpatch restore <ficheiro> --force` (com o serviço parado) e cópia diária automática (`BACKUP_*`); inclui **chaves privadas**: guarde-as cifradas e fora do servidor. Retenção opcional da auditoria e das tarefas concluídas (`AUDIT_RETENTION_DAYS`, `TASK_RETENTION_DAYS`; 0 = guardar sempre). PostgreSQL: cópia com `pg_dump` se existir.
- **CI** (`.github/workflows/ci.yml`): testes em Python 3.9/3.11/3.13 com cobertura mínima, `selftest` do agente em Windows, macOS e Linux de 3.8 a 3.13, lint, bandit e pip-audit. *Escrito mas ainda não executado no GitHub Actions.*

## Segurança

Isolamento por organização em todas as consultas; CSRF, CSP sem *inline*, cookies seguros, MFA TOTP (obrigatório por
organização), bloqueio por tentativas, auditoria (também por syslog para o SIEM); segredos das integrações cifrados (Fernet,
chave fora da base de dados); destinos de saída validados contra SSRF; aceitação de risco exige justificação; controlos e patches
exigem aprovação; portas de gestão (SSH/RDP/WinRM/SMB) protegidas contra bloqueio acidental; descoberta IoT/OT só por opção
explícita e apenas com ligação TCP; simulações BAS são verificações benignas (ficheiros canário num diretório temporário,
ligações TCP, leitura de configuração).

## Desenvolvimento

```bash
pip install -r requirements.txt pytest pyyaml        # + ansible jmespath para os testes dos playbooks
python -m pytest -q
```

Os testes cobrem risco e veredicto multi-vendor, parsers de NVD/KEV/EPSS/MITRE, correlação, Patch Intelligence, campanhas com anéis,
janelas, Wake-on-LAN, validação em ciclo fechado, controlos, IA, simulação, fluxo autónomo completo com **agentes simulados através
da API real**, todas as páginas, perfis e isolamento entre organizações, conectores (SIEM/SOAR/ITSM/EDR, OMXVuln, OMXGRC, descoberta)
e os playbooks (`--syntax-check` de todos e execução real de inventário/validação em localhost).

## Âmbito validado e limitações conhecidas

- **Testado:** servidor, motores, API, interface, agente em **Linux** (inventário real, firewall com comandos simulados), e os 17
  playbooks Ansible (sintaxe; inventário e validação executados de verdade).
- **Windows:** a sonda de origens, os comandos de cada instalador, os códigos de saída e a simulação foram testados com saídas simuladas (formatos de winget, choco, WUA e apt escritos de memória); nunca correram num Windows real. No Linux a simulação correu de verdade (`apt-get -s`).
- **Boas práticas:** nginx e Apache foram validados contra servidores reais (instalação, aplicação, `-t`, recarga, matriz TLS e
  reversão). O **IIS** (Schannel, WebAdministration) foi testado apenas com PowerShell simulado, nunca num Windows real; o TLS 1.3
  só é configurado em Windows build ≥ 20348 e o Schannel só vale após reiniciar. Sem boas práticas para macOS.
- **Não testado em sistemas reais:** os caminhos Windows e macOS do agente (registo, WUA/winget/MSI, softwareupdate/brew/pkg, netsh/pf,
  tarefa agendada/LaunchDaemon) e os playbooks Windows/macOS foram escritos e verificados quanto à sintaxe, mas nunca executados
  nesses sistemas; teste-os num anel de laboratório antes de os usar.
- **Conectores de terceiros:** os pedidos a Sentinel, Splunk HEC, Elastic, ServiceNow, Jira, Freshservice, Defender, CrowdStrike,
  SentinelOne, Entra, VMware, Azure, GCP, Kubernetes foram escritos segundo a documentação pública e testados com respostas
  simuladas, não contra instâncias reais. Para Tenable, Qualys, Rapid7, Wiz, Prisma, Check Point, Palo Alto, Fortinet e Zscaler a
  via fiável é o webhook/ficheiro (`/api/v1/signals`) com normalização por *aliases* de campos; a recolha por API exige indicar o
  caminho em *options.path*. A delegação de regras sem API segura (deteção EDR, WAF, NGFW por país) vai para SOAR/ITSM.
- A IA generativa é opcional e só redige a explicação; o plano e os números vêm do planeador determinístico.
