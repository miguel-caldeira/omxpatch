# Histórico de versões

A numeração é `1.<n>.<AAAAMMDD>`. Os pacotes de cada versão estão em `releases/<versão>/` (com `SHA256SUMS`).

## 1.40.20261128 — Acesso sem agente: WMI (Windows) e SSH (Linux)
- **Camada de transportes sem agente** (`omxpatch/transports`): SSH (paramiko; palavra-passe/chave, `sftp`, chave aceite na 1.ª ligação ou exigida, sudo) e **WMI/DCOM + SMB** (impacket) para Windows — sem WinRM e sem SSH no Windows.
- Nova ligação Ansible **`omx_wmi`**: os módulos do Ansible para Windows (win_updates, win_shell, win_copy…) correm sobre o WMI. O **WMI passa a ser o acesso por omissão ao Windows** sem agente (`ANSIBLE_WINDOWS_TRANSPORT`; WinRM e SSH por credencial ou ativo); o Linux usa SSH.
- Mecânica refeita: todos os trabalhos sem agente (inventário, validação, controlos, atualizações, CyberArk) usam o mesmo inventário com credenciais cifradas e a mesma resolução de transporte (o antigo inventário fixo em WinRM foi removido).
- **Testar ligação** por ativo (Motor Ansible): nome, portas, autenticação e comando real, com a causa e o remédio de cada falha.
- Dependências `impacket` e `paramiko` incluídas nos pacotes (offline); `omxpatch ansible-doctor` verifica-as.
- Testes: SSH real (sshd local, Ansible real), WMI contra um Windows simulado e Ansible real sobre `omx_wmi`. **WMI não testado em Windows real.**

## 1.39.20261123 — Agente como procuração (proxy) do Ansible e do PowerShell
- Nova ligação Ansible `omx_agent`: os comandos do Ansible são executados pelo agente do equipamento (PowerShell em Windows, shell POSIX nos restantes), sem WinRM, SSH nem portas de entrada; ficheiros por repositório temporário com SHA-256. Validado de ponta a ponta com o Ansible, o servidor e o agente reais (Linux).
- Agente: tarefa `exec` (executar/copiar/ler), permissão local obrigatória (`omxpatch-agent config allow-exec on`, `enroll --allow-exec`, `OMXPATCH_ALLOW_EXEC` nos instaladores) e ativação na consola (`AGENT_EXEC_ENABLED`); auditoria só com resumos; consulta de 1 s durante uma sessão de comandos.
- Motor Ansible: «Transporte do Ansible → agente» por ativo e repetição automática através do agente se a ligação direta falhar (`AGENT_EXEC_FALLBACK`). Agentes → Detalhe → «Execução remota» para comandos PowerShell/shell.
- Comandos e saídas são apagados da base de dados após a execução; limite de pedidos por agente elevado a 300/min.
- WMI/DCOM não implementado (ver manual 19.7).
- Corrigido: «Host key verification failed» — o SSH usa um `known_hosts` na pasta de dados do serviço (a «home» do utilizador do serviço é só de leitura) e aceita a chave na 1.ª ligação (`ANSIBLE_SSH_ACCEPT_NEW`, ou por credencial).
- Corrigido: uma firewall (FortiGate…) escolhida na atualização do SO era tratada como Linux; a consola explica que é um equipamento de rede e a «Avaliação de rede» assume a plataforma provável.

## 1.38.20261122 — Windows sem WinRM
- Credencial com «Windows: como ligar → SSH» (OpenSSH Server do Windows, palavra-passe ou chave SSH): o motor Ansible liga-se por SSH com shell PowerShell, sem WinRM. Uma credencial de chave SSH num ativo Windows usa SSH automaticamente.
- Manual: preparação do OpenSSH no Windows e a alternativa do agente (sem WinRM nem portas de entrada).

## 1.37.20261122 — Ligação WinRM/SSH do motor Ansible
- Erro «ssl: auth method ssl requires a username» (UNREACHABLE): faltava utilizador no ativo. A consola valida agora **antes de criar a tarefa** o que falta (utilizador, palavra-passe no Windows, token de API nos FortiGate/Palo Alto) e diz como corrigir.
- WinRM: NTLM sobre HTTPS por omissão, com o transporte (NTLM/Basic/CredSSP) e a validação do certificado configuráveis na credencial.
- O detalhe de cada trabalho explica em português os erros de ligação mais comuns (credenciais, certificado, rede/WinRM, SSH, sudo, coleções).

## 1.36.20261122 — Ansible deixava de arrancar com o utilizador do serviço
- **Causa real do «faltam coleções» e da versão vazia:** o utilizador do serviço (`omxpatch`) tem a «home» em `/opt/omxpatch` (só de leitura) e o Ansible recusava-se a arrancar («Unable to create local directories ~/.ansible/tmp»), nem `--version` funcionava. Qualquer tarefa Ansible falharia. O motor passa a usar `ANSIBLE_HOME` (e temporários e controlo SSH) na pasta de dados do próprio serviço.
- O diagnóstico já não confunde «a listagem de coleções falhou» com «coleções em falta» e mostra o erro quando o `ansible-playbook` existe mas não executa.

## 1.35.20261115 — Ansible: diagnóstico e correção
- «O Ansible não está disponível» passa a dizer **porquê** (servidor Windows, desativado na configuração, `ansible-playbook` não instalado, coleções em falta) e o comando exato que resolve, em Sistema e em Motor Ansible.
- Novo comando `omxpatch ansible-doctor [--fix --wheels … --collections …]`: diagnostica e instala o ansible-core, o WinRM e as coleções, e ativa o Ansible na configuração (sem tocar na base de dados nem criar pastas; seguro como root). `install.sh` e `update.sh` usam-no.
- Pacote Ubuntu: wheels também para Python 3.14 (Ubuntu 26.04) e coleções Ansible incluídas quando compilado com acesso ao Galaxy (instalação 100 % offline).

## 1.34.20261115 — Instaladores compiláveis nos SO de origem
- Novos construtores nativos: `packaging/build/linux/build.sh` (`.tar.gz`, `.deb` do servidor e do agente, `.rpm` do agente), `packaging/build/windows/build.ps1` (`.zip` e `.exe` Inno Setup do servidor, do servidor 2012 R2 e do agente) e `packaging/build/macos/build.sh` (`.pkg` do agente, com assinatura/notarização opcionais).
- Workflow `installers.yml`: compila cada instalador no seu SO, testa-os (instala o agente `.deb`/`.pkg`/`.exe`), junta tudo e pode criar uma Release ou guardar os ficheiros em `releases/`.
- Agente: inscrição automática por ficheiro (`enroll.env`) em Linux, macOS e Windows (MDM/GPO); novo `Install-OMXPatchAgent.ps1`.
- `build_installers.sh` aceita alvos (`ubuntu windows windows2012r2 kit agent`).

## 1.33.20261114 — CI
- Teste do `update.sh` compatível com Python 3.9.

## 1.32.20261114 — Ansible instalado e ativo por omissão
- Sistema mostrava «ansible-playbook não encontrado»: o Ansible só era instalado com `--with-ansible`, e mesmo instalado o serviço não o encontrava (o venv não está no PATH do systemd).
- `install.sh` instala agora o Ansible por omissão (wheels incluídos no pacote, offline; coleções do Galaxy se houver rede); `--no-ansible` para o saltar.
- `update.sh` instala o Ansible se faltar e ativa-o na configuração (`[ansible] enabled/playbook`).
- O servidor encontra o `ansible-playbook` também na pasta do próprio ambiente virtual; a mensagem do menu Sistema indica o comando de correção.

## 1.31.20261114 — FortiGate com Ansible antigo
- Avaliação de rede: as versões antigas do Ansible (2.15, habitual nas distribuições) entregam a resposta JSON do FortiGate já convertida em estrutura e a versão ficava vazia; o leitor aceita agora texto ou estrutura. Detetado pelo CI em Python 3.9.

## 1.30.20261114 — CI verde
- Testes compatíveis com Python 3.9; verificação de sintaxe cobre também os papéis (`roles/`); o teste real do inventário Linux só corre com a colecção `community.general` instalada.

## 1.29.20261114 — Correções do CI
- Agente: a consola do Windows (cp1252) fazia falhar a impressão do relatório de validação; a saída passa a tolerar caracteres não representáveis.
- Removidas duas importações não usadas (ruff).
- Testes: o agente nunca escreve em `/etc/omxpatch-agent` durante os testes; a verificação de sintaxe dos playbooks usa colecções simuladas; os testes que precisam de root só correm como root.

## 1.28.20261113 — Motor Ansible: atualização completa, CyberArk e equipamentos de rede
- **Motor Ansible sem agente** (menu «Motor Ansible»): atualiza o sistema operativo **e todo o software** em Windows (Windows Update, winget, Chocolatey), Linux (apt, dnf/yum, zypper, snap, flatpak) e macOS (softwareupdate, Homebrew, Mac App Store). Fluxo avaliar (só leitura) → OK do administrador → aplicar (avaliação das últimas 24 h obrigatória). As avaliações alimentam «Atualizações disponíveis».
- **CyberArk**: Vault, CPM, PSM (Windows) e PSMP (Linux) com pré-verificações, SHA-256 do pacote, cópia de segurança, ordem Vault → CPM → PSM → PSMP imposta, versão final confirmada e reposição dos serviços em caso de falha. O comando de atualização dos componentes Windows é fornecido pelo administrador (a validar em laboratório).
- **Switches, routers e firewalls** (Check Point, FortiGate, Palo Alto, Cisco IOS/NX-OS, Juniper, Arista): avaliação só de leitura, política de versões editável («Avaliação de rede»), versões disponíveis lidas do FortiGate/Palo Alto e cruzamento com CVE.
- Credenciais cifradas do motor (palavra-passe, chave SSH, token de API); ativos com plataforma de rede, componente CyberArk e credencial.
- Testes: playbooks verificados na sintaxe, Linux real no próprio servidor, macOS com executáveis simulados, e Windows/CyberArk/rede contra módulos, APIs e comandos simulados. Sem testes em equipamentos reais.
- Corrigido: nos testes, a criação das etapas CyberArk encadeava as dependências todas; agora cada etapa depende só da anterior.

## 1.27.20261109 — Windows Update: resolução definitiva
- O WUA deixa de pedir URL de transferência (inúteis: o Windows instala pelo Windows Update); a resposta passa de centenas de KB para poucos KB e cada atualização é lida de forma isolada.
- Depois de uma atualização do agente, a descoberta repete-se logo (no agente e por pedido da consola ao detetar a nova versão): deixam de ficar erros de versões anteriores no diagnóstico.

## 1.26.20261109 — Atualização do agente a partir da consola
- Corrigido: depois de atualizar, o agente relançava-se como `python …/__main__.py`, que falhava na importação relativa e deixava o agente desligado (sobretudo no Windows). Passa a relançar com `python -m omxpatch_agent` e o `__main__.py` também funciona como script (cobre agentes antigos a atualizar).
- «Atualizar agente» na consola faz mesmo a atualização (descarga, verificação, autoteste, troca) e reporta o resultado verdadeiro, incluindo falhas; sem pacote assinado publicado diz-o.
- A oferta de atualização é sempre publicada; `AGENT_AUTO_UPDATE` só controla a atualização automática (a manual da consola funciona na mesma).
- Atenção: agentes anteriores à 1.20 não têm comandos da consola; nestes a atualização automática relança o agente de forma errada no Windows — reinicie-os uma vez (`schtasks /Run /TN OMXPatchAgent`) ou reinstale.

## 1.25.20261109 — Versão instalada visível
- Consola: versão no topo e no rodapé; Sistema mostra «atualizada de X em data» e o histórico de versões (`<dados>/version.json`); `/healthz` devolve a versão em execução; Agentes mostra a versão da consola e marca os agentes desatualizados.
- Scripts de instalação e de atualização (Ubuntu e Windows) mostram a versão instalada antes/depois e confirmam a versão em execução na consola.

## 1.24.20261109 — Windows Update: causa real do erro
- Causa: a saída do PowerShell com centenas de atualizações (URL assinados muito longos) excedia o limite de 30 000 caracteres do agente e chegava truncada. O resultado vai agora por ficheiro (sem limite) e só se guarda o primeiro URL de cada atualização (os com mais de 1000 caracteres são ignorados: o Windows instala pelo próprio Windows Update).

## 1.23.20261109 — Windows Update por ficheiro
- O resultado do WUA volta por um ficheiro temporário UTF-8 (não pela saída padrão do PowerShell); em caso de falha o erro mostra o início do conteúdo recebido para diagnóstico.

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
