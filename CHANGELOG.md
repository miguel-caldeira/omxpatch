# Histórico de versões

A numeração é `1.<n>.<AAAAMMDD>`. Os pacotes de cada versão estão em `releases/<versão>/` (com `SHA256SUMS`).

## 1.22.20261109 — Agentes sem duplicados
- Reinstalar um agente reutiliza a mesma entrada (chave nova, histórico mantido) em vez de criar uma duplicada.
- Eliminar um agente já não dá erro interno (o histórico de descobertas fica, sem agente; os registos do agente saem).
- Novo botão «Eliminar revogados» em Agentes para limpar as entradas antigas.

## 1.21.20261109 — Correção do Windows Update e menu
- WUA: o JSON é extraído entre marcadores, ignorando o ruído do PowerShell (CLIXML); erros do PowerShell passam a ser mostrados em vez de «JSONDecodeError».
- Menu: «Organização» (definições do tenant atual) e «Tenants» (lista, super-administrador).

## 1.20.20261109 — Operação remota e registos dos agentes
- Página de detalhe do agente: registos de operação, auditoria e depuração (filtros, CSV), estado reportado, comandos recentes.
- Ações a partir da consola: depuração completa com validade, reiniciar, atualizar e pedir registos (tarefas assinadas; contacto de 5 em 5 min).
- O agente desliga-se (desativa o serviço) se não contactar a consola durante 2 h; recuo progressivo; eventos guardados localmente e reenviados.
- Todos os parâmetros editáveis em Sistema → Configuração: intervalo, tempo até desligar, depuração, envio/nível/retenção de registos.

## 1.19.20261109 — Windows Update (WUA) mais robusto
- O PowerShell do agente passa a usar `-EncodedCommand` (sem problemas de aspas/acentos) e saída UTF-8.
- A falha do WUA devolve o código HRESULT e uma explicação (rede/WSUS, acesso negado, serviço parado…), visível no Histórico de descobertas.

## 1.18.20261109 — Diagnóstico das atualizações
- Atualizações: painel «Diagnóstico por agente» (agente antigo, sem contacto, sem descoberta, origens com erro) e comando `omxpatch-agent updates [--send]` para diagnosticar e enviar a descoberta a partir do equipamento.

## 1.17.20261109 — Scripts de atualização
- Novos `update.sh` (Ubuntu) e `Update-OMXPatch.ps1`/`Atualizar.cmd` (Windows e 2012 R2): atualizam uma instalação existente, fazem cópia da configuração, forçam a reinstalação se a versão não mudar, reiniciam os serviços e verificam a versão final.

## 1.16.20261109 — Correção da atualização por cima de instalação existente
- Os instaladores Ubuntu e Windows usam `pip install --upgrade`: antes, numa máquina com uma versão antiga já instalada (ex.: 1.2), o pip considerava o OMXPatch «já satisfeito» e mantinha a versão antiga apesar de o pacote ser mais recente.

## 1.15.20261109 — Tenants em toda a interface
- Todas as referências visíveis a «organização» (menu, seletor, títulos, tabelas) passam a **Tenant**.

## 1.14.20261109 — Menu Tenants
- O menu e as páginas «Organizações» passam a **Tenants**, alinhado com o OMXVuln.

## 1.13.20261108 — Manuais de Administração e de Utilização
- **Manual de Utilização** e **Manual de Administração** (Markdown, Word e PDF, com capturas de ecrã) e **Referência técnica** gerada a partir do código (`docs/`).
- CI: o relatório de validação em Windows/macOS reais passa a aparecer no registo; teste do agente deixa de depender do sistema operativo.

## 1.12.20261108 — Validação em Windows e macOS reais
- Comando `python -m omxpatch_agent validate` (níveis `read` e `lab`, isolamento opcional) com relatório Markdown/JSON e redação de dados.
- Kit `omxpatch-validation-kit` (scripts Windows/macOS + checklist de laboratório) e job de CI `real-os-validation` em *runners* reais.
- Corrigido o CI dos testes em Windows/macOS (instalação com hashes).

## 1.11.20261108 — Fluxo Descoberta → Simulação → Remediação
- Contexto do ativo recolhido pelo agente (processos, escutas, firewall, acessos); **simulação de exposição** e **prioridade por perda esperada** no servidor.
- **Isolamento preventivo** do ativo; **linha de base** (gold images) com desvio e exportação; boas práticas `ssh_hardening` e `windows_hardening`.
- **Governação ITSM** (ServiceNow, Jira, Freshservice) para planos e controlos — **desativada por omissão**.

## 1.10.20261108 — Descoberta de atualizações instaláveis
- Descoberta nos agentes (apt, dnf/yum, zypper, Windows Update, winget, Chocolatey, softwareupdate, brew) com envio confirmado e reenvio garantido; descarga proativa verificada (SHA-256, anti-SSRF); simulação e remediação a partir do servidor.

## 1.9 / 1.8 — Pacotes reconstruídos; Centro de comando
- Dashboard gráfico consolidado com ações rápidas de simulação e remediação (sempre com OK).

## 1.7.20261108 — Endurecimento
- Rotação do thumbprint do certificado dos agentes, tarefas e pacote **assinados** (Ed25519), atualização automática do agente, limitação de pedidos, migrações versionadas, cópias e retenção, versões fixas com hashes, CI multi-SO.

## 1.6.20261108 — Capacidade, configuração e agentes multi-Python
- Análise de carga e escalabilidade, alteração de configuração com reinício controlado, agente em Python 3.8–3.13 e comunicação **só por IP + thumbprint**.

## 1.5.20261108 — Integração OMXVuln
- Importação de ativos e vulnerabilidades com simulação prévia.

## 1.4.20261108 — Windows Server 2012 R2
- Instalador próprio (Python 3.11, verificações prévias).

## 1.3 / 1.2 / 1.1 — Instaladores, Windows e boas práticas
- Python/pip incluídos nos instaladores; instalação robusta do Python no Windows e BOM nos `.ps1`; boas práticas (TLS 1.2/1.3 em IIS, Apache, nginx) e planos de operações com simulação e OK; origens de atualização Windows e simulação prévia de patches.

## 1.0 — Base
- Centro de comando multi-organização (porta 4434) e agentes (porta 4444) com dois certificados autoassinados; 15 módulos (inventário/CMDB, inteligência, exposição multi-vendor, risco dinâmico, patching, anéis, controlos compensatórios, IA, validação em ciclo fechado, integrações, conformidade, painel executivo, BAS, remediação autónoma); Ansible; instaladores Ubuntu e Windows.
