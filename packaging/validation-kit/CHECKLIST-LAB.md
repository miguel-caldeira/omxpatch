# Checklist de laboratório — Windows e macOS

Para cada caso: execute, compare com o **esperado** e registe ✅/❌ + observações. Use uma VM com *snapshot* antes de começar.

## A. Automático (o script faz sozinho)
| # | Caso | Windows | macOS |
|---|---|---|---|
| A1 | Autoteste do agente | ✅ | ✅ |
| A2 | Inventário (software, portas, SO) | registo + `Get-HotFix` | `system_profiler` (lento, ~1–2 min) + brew |
| A3 | Descoberta de atualizações | WUA, winget, choco | `softwareupdate -l`, brew |
| A4 | Contexto do ativo | `Get-NetTCPConnection`, firewall por perfil, Administradores, RDP/NLA/SMB1/Defender | `lsof`, ALF, grupo admin, SIP |
| A5 | Firewall de teste (lab) | `netsh advfirewall` | `pf` (âncora `omxpatch`) |
| A6 | Endurecimento aplicar→reverter (lab) | SMBv1 / RDP NLA | `sshd -t` + drop-in |
| A7 | Consola por IP + thumbprint (com `-Server/-Pin`) | ✅ | ✅ |

## B. Manual (instalar o agente de verdade e usar a consola)
1. **Registo por IP:** gere o script de instalação com `AGENT_ADDRESS_MODE=ip`; confirme que **não** altera o ficheiro hosts e que o agente fica online. *Esperado:* agente online na consola em ≤ 1 contacto.
2. **Descoberta chega à consola:** *Atualizações → Descobrir agora*. *Esperado:* linha em «Histórico de descobertas» com o total e as origens; ativos com `wua`/`winget` ou `softwareupdate`.
3. **Descarga proativa (winget):** num PC com apps desatualizadas. *Esperado:* itens `winget` MSI/EXE com URL e SHA-256 passam a «No repositório do servidor»; `wua`/macOS ficam «usam a origem do SO».
4. **Simular → OK → instalar um MSI/EXE do servidor:** *Esperado:* simulação mostra assinatura e versão; instalar só após OK; versão nova no inventário seguinte.
5. **Windows Update (WUA):** simulação e instalação de um KB; *Esperado:* códigos 0/3010 tratados; reinício conforme a política.
6. **macOS `softwareupdate`:** simular e instalar uma atualização com **nome com espaços** (`macOS Sonoma 14.5-23F79`). *Esperado:* aceite e instalada.
7. **Boa prática IIS (Windows Server):** TLS 1.2/1.3 — simular, OK, aplicar; *Esperado:* Schannel alterado, reinício pendente indicado; reverter repõe os valores.
8. **SMBv1/NLA:** num Windows com SMBv1 ligado e RDP sem NLA — simular e aplicar; *Esperado:* ambos corrigidos; reverter repõe.
9. **Isolamento:** *Ativo → Propor isolamento* (30 min) → aprovar → aplicar. *Esperado:* consola continua a ver o agente; ping/Internet a falhar; ao libertar ou ao expirar o prazo tudo volta. **Plano B:** acesso à VM pela consola do hipervisor.
   - Windows: `Get-NetFirewallProfile` mostra Block/Block durante o isolamento e os valores originais depois.
   - macOS: `sudo pfctl -a omxpatch-isolate -s rules` mostra `block drop quick all` durante o isolamento.
10. **Rotação de certificado:** forçar a preparação do certificado seguinte (certificado a <60 dias) e confirmar que o agente adota os dois thumbprints e continua online depois da troca.
11. **Tarefas assinadas:** alterar manualmente o `payload` de uma tarefa na base de dados antes do agente a descarregar. *Esperado:* o agente recusa («assinatura inválida»).
12. **Atualização automática do agente:** publicar uma versão superior. *Esperado:* o agente descarrega, valida a assinatura, corre o autoteste, troca a pasta e reinicia; `omxpatch_agent.prev` fica para reversão.

## C. Registo dos resultados
Versão do agente, SO/versão/build, Python, administrador?, resultado de cada caso, mensagens de erro completas (sem dados sensíveis).
