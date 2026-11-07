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

- **entrada:** `GET /findings` → ativos + exposições (CVE, software, versão instalada, versão corrigida, KEV/EPSS); o OMXVuln é a
  fonte de verdade da deteção. Uma deteção que desaparece do OMXVuln passa a *remediada* e é validada.
- **saída:** após a validação em ciclo fechado, `POST /findings/<id>/status` (*remediada*) e `POST /scans` ao alvo do ativo, para o
  OMXVuln fechar a deteção com verificação independente.

**OMXGRC** — em *Integrações → OMXGRC* ou `[omxgrc]`:

- **push:** métricas dos cinco referenciais (`POST <metrics_path>`) e uma **evidência** por remediação validada (`POST <evidence_path>`);
- **pull:** `GET /api/v1/grc/controls` e `GET /api/v1/grc/evidence` neste servidor.

> Os caminhos do OMXGRC são configuráveis porque o contrato exato da API do OMXGRC não foi consultado; ajuste-os se diferirem.

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
`/grc/controls`, `/grc/evidence`, `/enrollment-tokens`.

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
- **Não testado em sistemas reais:** os caminhos Windows e macOS do agente (registo, WUA/winget/MSI, softwareupdate/brew/pkg, netsh/pf,
  tarefa agendada/LaunchDaemon) e os playbooks Windows/macOS foram escritos e verificados quanto à sintaxe, mas nunca executados
  nesses sistemas; teste-os num anel de laboratório antes de os usar.
- **Conectores de terceiros:** os pedidos a Sentinel, Splunk HEC, Elastic, ServiceNow, Jira, Freshservice, Defender, CrowdStrike,
  SentinelOne, Entra, VMware, Azure, GCP, Kubernetes foram escritos segundo a documentação pública e testados com respostas
  simuladas, não contra instâncias reais. Para Tenable, Qualys, Rapid7, Wiz, Prisma, Check Point, Palo Alto, Fortinet e Zscaler a
  via fiável é o webhook/ficheiro (`/api/v1/signals`) com normalização por *aliases* de campos; a recolha por API exige indicar o
  caminho em *options.path*. A delegação de regras sem API segura (deteção EDR, WAF, NGFW por país) vai para SOAR/ITSM.
- A IA generativa é opcional e só redige a explicação; o plano e os números vêm do planeador determinístico.
