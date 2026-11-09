# Referência técnica — OMXPatch 1.22.20261109

> Gerada automaticamente a partir do código (`python docs/tools/gen_reference.py`). Não editar à mão.

## Perfis

- **admin** — Administrador
- **user** — Operador
- **auditor** — Auditor (só leitura)
- **superadmin** — administra todas as organizações e o sistema (sem organização própria).

## Parâmetros de configuração

Ordem de precedência: variável de ambiente `OMXPATCH_<NOME>` › `omxpatch.overrides.toml` (alterações feitas na consola) › `omxpatch.toml` › omissão.

| Parâmetro (`OMXPATCH_<NOME>`) | TOML | Omissão |
|---|---|---|
| `HOST` | `[server] host` | (vazio) |
| `PORT` | `[server] port` | `4434` |
| `TLS_ENABLED` | `[server] tls_enabled` | sim |
| `AGENT_PORT` | `[agents] port` | `4444` |
| `AGENT_TLS_HOSTNAME` | `[agents] tls_hostname` | `omxpatchcli.oramix.local` |
| `AGENT_TLS_EXTRA_NAMES` | `[agents] tls_extra_names` | (vazio) |
| `AGENT_TLS_CERT` | `[agents] tls_cert` | (vazio) |
| `AGENT_TLS_KEY` | `[agents] tls_key` | (vazio) |
| `AGENT_SERVER_IP` | `[agents] server_ip` | (vazio) |
| `AGENT_BASE_URL` | `[agents] base_url` | (vazio) |
| `AGENT_ADDRESS_MODE` | `[agents] address_mode` | `name` |
| `IMPACT_CURRENCY` | `[server] impact_currency` | `EUR` |
| `IMPACT_OUTAGE_HOURS` | `[server] impact_outage_hours` | `24` |
| `IMPACT_COST_LOW` | `[server] impact_cost_low` | `100` |
| `IMPACT_COST_MEDIUM` | `[server] impact_cost_medium` | `1000` |
| `IMPACT_COST_HIGH` | `[server] impact_cost_high` | `5000` |
| `IMPACT_COST_CRITICAL` | `[server] impact_cost_critical` | `20000` |
| `CONTEXT_EVERY_HOURS` | `[server] context_every_hours` | `24` |
| `UPDATES_SCAN_HOURS` | `[server] updates_scan_hours` | `6` |
| `UPDATES_AUTO_DOWNLOAD` | `[server] updates_auto_download` | sim |
| `UPDATES_DOWNLOAD_PER_TICK` | `[server] updates_download_per_tick` | `3` |
| `UPDATES_MAX_DOWNLOAD_MB` | `[server] updates_max_download_mb` | `1024` |
| `UPDATES_ALLOW_UNHASHED` | `[server] updates_allow_unhashed` | não |
| `UPDATES_ALLOW_HTTP_WITH_HASH` | `[server] updates_allow_http_with_hash` | sim |
| `BACKUP_ENABLED` | `[server] backup_enabled` | sim |
| `BACKUP_HOURS` | `[server] backup_hours` | `24` |
| `BACKUP_KEEP` | `[server] backup_keep` | `7` |
| `BACKUP_DIR` | `[server] backup_dir` | (vazio) |
| `AUDIT_RETENTION_DAYS` | `[server] audit_retention_days` | `0` |
| `TASK_RETENTION_DAYS` | `[server] task_retention_days` | `0` |
| `RATE_ENROLL_PER_MIN` | `[server] rate_enroll_per_min` | `120` |
| `RATE_AUTH_FAIL_PER_MIN` | `[server] rate_auth_fail_per_min` | `30` |
| `RATE_AGENT_PER_MIN` | `[server] rate_agent_per_min` | `120` |
| `AGENT_AUTO_UPDATE` | `[agents] auto_update` | sim |
| `AGENT_SERVER_URLS` | `[agents] server_urls` | (vazio) |
| `TLS_HOSTNAME` | `[server] tls_hostname` | `omxpatch.oramix.local` |
| `TLS_EXTRA_NAMES` | `[server] tls_extra_names` | (vazio) |
| `TLS_CERT` | `[server] tls_cert` | (vazio) |
| `TLS_KEY` | `[server] tls_key` | (vazio) |
| `TLS_DAYS` | `[server] tls_days` | `730` |
| `TLS_MIN_VERSION` | `[server] tls_min_version` | `1.2` |
| `URL_PREFIX` | `[server] url_prefix` | (vazio) |
| `TRUSTED_PROXIES` | `[server] trusted_proxies` | `1` |
| `SESSION_COOKIE_SECURE` | `[server] session_cookie_secure` | não |
| `SESSION_HOURS` | `[server] session_hours` | `8` |
| `FRAME_ANCESTORS` | `[server] frame_ancestors` | `'self'` |
| `SECRET_KEY` | `[server] secret_key` | (segredo) |
| `DATABASE_URL` | `[server] database_url` | (vazio) |
| `MAX_UPLOAD_MB` | `[server] max_upload_mb` | `500` |
| `THREADS` | `[server] threads` | `8` |
| `BASE_URL` | `[server] base_url` | (vazio) |
| `EMBEDDED_WORKER` | `[server] embedded_worker` | sim |
| `WORKER_POLL_SECONDS` | `[worker] poll_seconds` | `15` |
| `INTEL_SYNC_HOURS` | `[intel] sync_hours` | `24` |
| `CORRELATE_MINUTES` | `[server] correlate_minutes` | `15` |
| `PASSWORD_MIN_LENGTH` | `[server] password_min_length` | `12` |
| `MFA_ISSUER` | `[server] mfa_issuer` | `OMXPatch` |
| `LOGIN_MAX_FAILURES` | `[server] login_max_failures` | `5` |
| `LOGIN_LOCK_MINUTES` | `[server] login_lock_minutes` | `15` |
| `ALLOW_LOOPBACK_OUTBOUND` | `[server] allow_loopback_outbound` | não |
| `LICENSE_GRACE_DAYS` | `[licensing] grace_days` | `15` |
| `LICENSE_WARN_DAYS` | `[licensing] warn_days` | `30` |
| `AGENT_HEARTBEAT_SECONDS` | `[agents] heartbeat_seconds` | `300` |
| `AGENT_GIVEUP_MINUTES` | `[agents] giveup_minutes` | `120` |
| `AGENT_DEBUG_DEFAULT_MINUTES` | `[agents] debug_default_minutes` | `60` |
| `AGENT_LOG_UPLOAD` | `[agents] log_upload` | sim |
| `AGENT_LOG_LEVEL` | `[agents] log_level` | `info` |
| `AGENT_LOG_MAX_BATCH` | `[agents] log_max_batch` | `200` |
| `AGENT_LOG_RETENTION_DAYS` | `[agents] log_retention_days` | `30` |
| `AGENT_OFFLINE_MINUTES` | `[agents] offline_minutes` | `20` |
| `AGENT_TASK_TIMEOUT_MINUTES` | `[agents] task_timeout_minutes` | `120` |
| `AGENT_PACKAGE_DIR` | `[agents] package_dir` | (vazio) |
| `BANDWIDTH_DEFAULT_KBPS` | `[server] bandwidth_default_kbps` | `0` |
| `ANSIBLE_ENABLED` | `[ansible] enabled` | sim |
| `ANSIBLE_PLAYBOOK` | `[ansible] playbook` | `ansible-playbook` |
| `ANSIBLE_DIR` | `[ansible] dir` | (vazio) |
| `ANSIBLE_INVENTORY` | `[ansible] inventory` | (vazio) |
| `ANSIBLE_TIMEOUT_MINUTES` | `[ansible] timeout_minutes` | `90` |
| `KEV_ENABLED` | `[kev] enabled` | sim |
| `KEV_URL` | `[kev] url` | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |
| `EPSS_ENABLED` | `[epss] enabled` | sim |
| `EPSS_URL` | `[epss] url` | `https://api.first.org/data/v1/epss` |
| `NVD_ENABLED` | `[nvd] enabled` | sim |
| `NVD_URL` | `[nvd] url` | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| `NVD_API_KEY` | `[nvd] api_key` | (segredo) |
| `NVD_BUDGET` | `[nvd] budget` | `40` |
| `MITRE_ENABLED` | `[mitre] enabled` | sim |
| `MITRE_URL` | `[mitre] url` | `https://cveawg.mitre.org/api/cve` |
| `THREAT_FEEDS` | `[server] threat_feeds` | (vazio) |
| `VENDOR_ADVISORIES` | `[server] vendor_advisories` | (vazio) |
| `OMXVULN_URL` | `[omxvuln] url` | (vazio) |
| `OMXVULN_TOKEN` | `[omxvuln] token` | (segredo) |
| `OMXVULN_TENANT_ID` | `[omxvuln] tenant_id` | `0` |
| `OMXVULN_VERIFY_TLS` | `[omxvuln] verify_tls` | sim |
| `OMXVULN_SYNC_MINUTES` | `[omxvuln] sync_minutes` | `30` |
| `OMXVULN_PUSH_STATUS` | `[omxvuln] push_status` | sim |
| `OMXVULN_RESCAN` | `[omxvuln] rescan` | sim |
| `OMXGRC_URL` | `[omxgrc] url` | (vazio) |
| `OMXGRC_TOKEN` | `[omxgrc] token` | (segredo) |
| `OMXGRC_VERIFY_TLS` | `[omxgrc] verify_tls` | sim |
| `OMXGRC_PUSH_MINUTES` | `[omxgrc] push_minutes` | `60` |
| `OMXGRC_EVIDENCE_PATH` | `[omxgrc] evidence_path` | `/api/v1/evidence` |
| `OMXGRC_METRICS_PATH` | `[omxgrc] metrics_path` | `/api/v1/metrics` |
| `AI_ENABLED` | `[ai] enabled` | não |
| `AI_API_KEY` | `[ai] api_key` | (segredo) |
| `AI_URL` | `[ai] url` | `https://api.anthropic.com/v1/messages` |
| `AI_MODEL` | `[ai] model` | `claude-sonnet-5-5` |
| `AI_TIMEOUT` | `[ai] timeout` | `60` |
| `RING_MIN_SUCCESS` | `[rings] min_success` | `95.0` |
| `RING_MAX_CRASH` | `[rings] max_crash` | `1.0` |
| `RING_MIN_UX` | `[rings] min_ux` | `80.0` |
| `RING_MIN_DEVICES` | `[rings] min_devices` | `1` |
| `RING_SOAK_HOURS` | `[rings] soak_hours` | `24` |
| `SMTP_HOST` | `[smtp] host` | (vazio) |
| `SMTP_PORT` | `[smtp] port` | `587` |
| `SMTP_USERNAME` | `[smtp] username` | (vazio) |
| `SMTP_PASSWORD` | `[smtp] password` | (segredo) |
| `SMTP_STARTTLS` | `[smtp] starttls` | sim |
| `SMTP_SSL` | `[smtp] ssl` | não |
| `SMTP_TIMEOUT` | `[smtp] timeout` | `30` |
| `MAIL_FROM` | `[server] mail_from` | `omxpatch@localhost` |
| `NOTIFY_ASYNC` | `[server] notify_async` | sim |
| `SYSLOG_ENABLED` | `[syslog] enabled` | não |
| `SYSLOG_HOST` | `[syslog] host` | (vazio) |
| `SYSLOG_PORT` | `[syslog] port` | `514` |
| `SYSLOG_PROTOCOL` | `[syslog] protocol` | `udp` |
| `SYSLOG_FORMAT` | `[syslog] format` | `rfc5424` |
| `SYSLOG_FACILITY` | `[syslog] facility` | `16` |
| `SYSLOG_VERIFY_TLS` | `[syslog] verify_tls` | sim |

## Comandos `omxpatch`

| Comando | Utilização |
|---|---|
| `agent-token` | `omxpatch agent-token [-h] --tenant TENANT [--ring RING] [--days DAYS] [--name NAME] [--max-uses MAX_USES]` |
| `ansible-vars` | `omxpatch ansible-vars [-h] --tenant TENANT [--ring RING] [--days DAYS] [--name NAME] [--max-uses MAX_USES]` |
| `backup` | `omxpatch backup [-h] [{create,list}]` |
| `capacity` | `omxpatch capacity [-h] [--benchmark] [--agents AGENTS] [--seconds SECONDS] [--tenant TENANT] [--json]` |
| `check` | `omxpatch check [-h]` |
| `correlate` | `omxpatch correlate [-h] --tenant TENANT` |
| `create-tenant` | `omxpatch create-tenant [-h] --name NAME [--slug SLUG] [--admin-email ADMIN_EMAIL] [--license-until LICENSE_UNTIL]` |
| `db` | `omxpatch db [-h] {status,upgrade}` |
| `import-intel` | `omxpatch import-intel [-h] file` |
| `init` | `omxpatch init [-h] --email EMAIL [--password PASSWORD] [--tenant TENANT]` |
| `initial-password` | `omxpatch initial-password [-h]` |
| `intel-sync` | `omxpatch intel-sync [-h]` |
| `reset-admin` | `omxpatch reset-admin [-h] [--email EMAIL] [--reset-mfa]` |
| `restore` | `omxpatch restore [-h] [--force] file` |
| `serve` | `omxpatch serve [-h] [--host HOST] [--port PORT] [--agent-port AGENT_PORT] [--prefix PREFIX] [--no-worker] [--no-tls]` |
| `signing` | `omxpatch signing [-h] {show,rotate}` |
| `tls` | `omxpatch tls [-h] [--hostname HOSTNAME] [--agent-hostname AGENT_HOSTNAME] [--days DAYS] {info,generate}` |
| `worker` | `omxpatch worker [-h]` |

## Comandos `omxpatch_agent`

| Comando | Utilização |
|---|---|
| `enroll` | `omxpatch-agent enroll [-h] --server SERVER --token TOKEN [--pin-sha256 PIN_SHA256] [--ca-file CA_FILE] [--install-service] [--force]` |
| `install-service` | `omxpatch-agent install-service [-h]` |
| `inventory` | `omxpatch-agent inventory [-h]` |
| `once` | `omxpatch-agent once [-h]` |
| `run` | `omxpatch-agent run [-h]` |
| `selftest` | `omxpatch-agent selftest [-h] [--json]` |
| `status` | `omxpatch-agent status [-h]` |
| `uninstall-service` | `omxpatch-agent uninstall-service [-h]` |
| `updates` | `omxpatch-agent updates [-h] [--send] [--no-refresh] [--limit LIMIT]` |
| `validate` | `omxpatch-agent validate [-h] [--level {read,lab}] [--yes-lab] [--with-isolation] [--server SERVER] [--pin PIN] [--json JSON] [--report REPORT] [--no-redact] [--quiet]` |

## Tipos de tarefa

| Tipo | Descrição |
|---|---|
| `update_scan` | Descobrir atualizações |
| `practice_sim` | Simulação de boa prática |
| `practice_apply` | Aplicar boa prática |
| `practice_rollback` | Reverter boa prática |
| `simulate` | Simulação prévia |
| `inventory` | Inventário |
| `patch` | Aplicar patch |
| `validate` | Validar |
| `bas` | Simulação (BAS) |
| `control` | Controlo compensatório |
| `rollback` | Reverter patch |
| `wake` | Wake-on-LAN |
| `agent_ctl` | Comando ao agente |

## Boas práticas

| Boa prática | Aplica-se a | Risco | Parâmetros |
|---|---|---|---|
| `tls_protocols` — TLS 1.2 e 1.3 apenas, com cifras seguras | nginx, apache, iis | médio | `tls13`, `scope` |
| `hsts` — HSTS (Strict-Transport-Security) | nginx, apache, iis | alto | `max_age`, `include_subdomains`, `preload` |
| `hide_version` — Ocultar a versão do servidor | nginx, apache, iis | baixo | — |
| `security_headers` — Cabeçalhos de segurança (nosniff, X-Frame-Options, Referrer-Policy) | nginx, apache, iis | baixo | — |
| `ssh_hardening` — SSH: sem root, sem palavras-passe vazias (e sem palavra-passe, se houver chaves) | linux, macos | médio | `disable_password` |
| `windows_hardening` — Windows: desativar SMBv1 e exigir NLA no RDP | windows | médio | — |

## Integrações

| Grupo | Integração (`kind`) | Opções |
|---|---|---|
| Vulnerabilidades (ferramentas irmãs) | OMXVuln (vulnerabilidades) (`omxvuln`) | `tenant_id`, `push_status`, `rescan`, `min_status`, `sync_assets`, `min_severity`, `assets_path` |
| GRC | OMXGRC (governação, risco e conformidade) (`omxgrc`) | `evidence_path`, `metrics_path` |
| SIEM | Microsoft Sentinel (Logs Ingestion) (`sentinel`) | `path` |
| SIEM | Splunk (HTTP Event Collector) (`splunk`) | `path`, `index` |
| SIEM | IBM QRadar (syslog LEEF) (`qradar`) | `host`, `port`, `protocol` |
| SIEM | Elastic (Elasticsearch / Security) (`elastic`) | `index` |
| SOAR | Cortex XSOAR (`xsoar`) | `path`, `incident_type` |
| SOAR | Microsoft Sentinel Automation (Logic App webhook) (`sentinel_automation`) | `path` |
| SOAR | Tines (webhook) (`tines`) | `path` |
| ITSM | ServiceNow (incidentes + CMDB) (`servicenow`) | `cmdb_table`, `change_management`, `change_type`, `assignment_group`, `approved_states` |
| ITSM | Jira Cloud (`jira`) | `project`, `issue_type`, `change_management`, `change_issue_type`, `approved_statuses`, `rejected_statuses` |
| ITSM | Freshservice (`freshservice`) | `requester_email`, `change_management`, `approved_status_ids`, `rejected_status_ids` |
| EDR | Microsoft Defender XDR (`defender`) | `vuln_path` |
| EDR | SentinelOne (`sentinelone`) | `vuln_path` |
| EDR | CrowdStrike Falcon (`crowdstrike`) | `vuln_path` |
| Gestão de vulnerabilidades | Tenable (`tenable`) | `path` |
| Gestão de vulnerabilidades | Qualys (`qualys`) | `path` |
| Gestão de vulnerabilidades | Rapid7 InsightVM (`rapid7`) | `path` |
| Cloud / CSPM | Wiz (`wiz`) | `path` |
| Cloud / CSPM | Prisma Cloud (`prisma`) | `path` |
| Firewalls de rede | Check Point (`checkpoint`) | `path` |
| Firewalls de rede | Palo Alto Networks (`paloalto`) | `path` |
| Firewalls de rede | Fortinet FortiGate (`fortinet`) | `path` |
| Firewalls de rede | Zscaler (`zscaler`) | `path` |
| Descoberta de ativos | Active Directory (LDAP) (`ad`) | `base_dn` |
| Descoberta de ativos | Microsoft Entra ID (Graph) (`entra`) | — |
| Descoberta de ativos | VMware vSphere (`vmware`) | — |
| Descoberta de ativos | Microsoft Hyper-V (via Ansible/WinRM) (`hyperv`) | `hosts` |
| Descoberta de ativos | AWS (EC2) — requer boto3 (`aws`) | `regions` |
| Descoberta de ativos | Azure (VMs) (`azure`) | `subscription_id` |
| Descoberta de ativos | Google Cloud (Compute) (`gcp`) | `project` |
| Descoberta de ativos | Kubernetes / contentores (`k8s`) | `cluster` |

## Rotas da consola e perfil mínimo

| Módulo | Rota | Métodos | Perfil exigido |
|---|---|---|---|
| admin | `/users` | GET | admin |
| admin | `/users/new` | GET,POST | admin |
| admin | `/users/<int:user_id>` | GET,POST | admin |
| admin | `/tenants` | GET | superadmin |
| admin | `/tenants/new` | GET,POST | superadmin |
| admin | `/tenants/<int:tenant_id>/license` | POST | superadmin |
| admin | `/settings` | GET,POST | admin |
| admin | `/audit` | GET | admin/auditor |
| admin | `/system` | GET | superadmin |
| admin | `/system/capacity` | GET,POST | superadmin |
| admin | `/system/backup` | POST | superadmin |
| admin | `/system/capacity.json` | GET | superadmin |
| admin | `/system/settings` | GET,POST | superadmin |
| admin | `/system/restart` | POST | superadmin |
| admin | `/integrations` | GET | admin |
| admin | `/integrations/<kind>` | GET,POST | admin |
| admin | `/integrations/omxvuln/import` | GET,POST | admin |
| admin | `/integrations/<kind>/<action>` | POST | admin |
| admin | `/agents` | GET | admin/auditor/user |
| admin | `/agents/script` | POST | admin |
| admin | `/agents/uninstall/<os_kind>` | GET | admin |
| admin | `/agents/<int:agent_id>/delete` | POST | admin |
| admin | `/agents/tokens` | POST | admin |
| admin | `/agents/tokens/<int:token_id>/revoke` | POST | admin |
| admin | `/agents/<int:agent_id>/revoke` | POST | admin |
| admin | `/agents/<int:agent_id>` | GET | admin/auditor/user |
| admin | `/agents/<int:agent_id>/command` | POST | admin |
| admin | `/agents/<int:agent_id>/logs.csv` | GET | admin/auditor |
| admin | `/agents/purge-revoked` | POST | admin |
| auth | `/login` | GET,POST | qualquer utilizador autenticado |
| auth | `/mfa` | GET,POST | qualquer utilizador autenticado |
| auth | `/mfa/setup` | GET,POST | qualquer utilizador autenticado |
| auth | `/mfa/recovery` | GET,POST | qualquer utilizador autenticado |
| auth | `/mfa/disable` | POST | qualquer utilizador autenticado |
| auth | `/logout` | POST | qualquer utilizador autenticado |
| auth | `/password` | GET,POST | qualquer utilizador autenticado |
| auth | `/profile` | GET | qualquer utilizador autenticado |
| auth | `/profile/tokens` | POST | qualquer utilizador autenticado |
| auth | `/profile/tokens/<int:token_id>/delete` | POST | qualquer utilizador autenticado |
| auth | `/tenant/select` | POST | qualquer utilizador autenticado |
| baseline | `/baseline` | GET | qualquer utilizador autenticado |
| baseline | `/baseline/export` | GET | qualquer utilizador autenticado |
| baseline | `/baseline/add` | POST | admin/user |
| baseline | `/baseline/<int:item_id>/remove` | POST | admin/user |
| branding | `/branding/theme.css` | GET | qualquer utilizador autenticado |
| branding | `/branding/logo/<int:tenant_id>` | GET | qualquer utilizador autenticado |
| branding | `/branding/settings` | POST | qualquer utilizador autenticado |
| main | `/` | GET | qualquer utilizador autenticado |
| main | `/executive` | GET | qualquer utilizador autenticado |
| main | `/command/quick` | POST | admin/user |
| main | `/assets` | GET | qualquer utilizador autenticado |
| main | `/assets/new` | GET,POST | admin/user |
| main | `/assets/<int:asset_id>` | GET | qualquer utilizador autenticado |
| main | `/assets/<int:asset_id>/edit` | GET,POST | admin/user |
| main | `/assets/<int:asset_id>/delete` | POST | admin |
| main | `/assets/<int:asset_id>/inventory` | POST | admin/user |
| main | `/assets/discover` | POST | admin |
| main | `/assets/import` | POST | admin |
| main | `/exposures` | GET | qualquer utilizador autenticado |
| main | `/exposures/<int:exposure_id>` | GET | qualquer utilizador autenticado |
| main | `/exposures/correlate` | POST | admin/user |
| main | `/exposures/<int:exposure_id>/accept` | POST | admin |
| main | `/exposures/<int:exposure_id>/reopen` | POST | admin |
| main | `/exposures/<int:exposure_id>/validate` | POST | admin/user |
| main | `/exposures/<int:exposure_id>/notify` | POST | admin/user |
| main | `/intel` | GET | qualquer utilizador autenticado |
| main | `/intel/<cve_id>` | GET | qualquer utilizador autenticado |
| main | `/intel/sync` | POST | admin |
| main | `/intel/import` | POST | admin |
| main | `/intel/<cve_id>/enrich` | POST | admin/user |
| main | `/signals` | GET | qualquer utilizador autenticado |
| main | `/signals/import` | POST | admin/user |
| main | `/assets/<int:asset_id>/isolate` | POST | admin/user |
| patching | `/patches` | GET | qualquer utilizador autenticado |
| patching | `/patches/new` | GET,POST | admin/user |
| patching | `/patches/<int:patch_id>` | GET | qualquer utilizador autenticado |
| patching | `/patches/identify` | POST | admin/user |
| patching | `/patches/<int:patch_id>/status` | POST | admin |
| patching | `/patches/<int:patch_id>/upload` | POST | admin/user |
| patching | `/patches/<int:patch_id>/download` | POST | admin/user |
| patching | `/patches/<int:patch_id>/file` | GET | qualquer utilizador autenticado |
| patching | `/patches/<int:patch_id>/community` | POST | admin |
| patching | `/campaigns` | GET | qualquer utilizador autenticado |
| patching | `/campaigns/new` | GET,POST | admin/user |
| patching | `/campaigns/<int:campaign_id>` | GET | qualquer utilizador autenticado |
| patching | `/campaigns/<int:campaign_id>/<action>` | POST | admin/user |
| patching | `/tasks/<int:task_id>` | GET | qualquer utilizador autenticado |
| patching | `/tasks/<int:task_id>/retry` | POST | admin/user |
| patching | `/windows` | GET,POST | admin/user/auditor |
| patching | `/windows/<int:window_id>/delete` | POST | admin |
| patching | `/rings` | GET,POST | qualquer utilizador autenticado |
| patching | `/rings/assign` | POST | admin |
| patching | `/assets/<int:asset_id>/ring` | POST | admin/user |
| patching | `/patches/<int:patch_id>/simulate` | POST | admin/user |
| patching | `/preflights` | GET | qualquer utilizador autenticado |
| patching | `/preflights/<int:pf_id>` | GET | qualquer utilizador autenticado |
| patching | `/preflights/<int:pf_id>/rerun` | POST | admin/user |
| patching | `/sources` | GET | qualquer utilizador autenticado |
| plans | `/practices` | GET | qualquer utilizador autenticado |
| plans | `/plans` | GET | qualquer utilizador autenticado |
| plans | `/plans/new` | GET,POST | admin/user |
| plans | `/plans/<int:plan_id>` | GET | qualquer utilizador autenticado |
| plans | `/plans/<int:plan_id>/<action>` | POST | admin/user |
| plans | `/plans/items/<int:item_id>` | GET | qualquer utilizador autenticado |
| plans | `/plans/items/<int:item_id>/revert` | POST | admin |
| secops | `/controls` | GET | qualquer utilizador autenticado |
| secops | `/controls/<int:control_id>` | GET | qualquer utilizador autenticado |
| secops | `/exposures/<int:exposure_id>/controls/propose` | POST | admin/user |
| secops | `/exposures/<int:exposure_id>/controls/new` | POST | admin/user |
| secops | `/controls/<int:control_id>/<action>` | POST | admin |
| secops | `/advisor` | GET,POST | qualquer utilizador autenticado |
| secops | `/advisor/<int:plan_id>` | GET | qualquer utilizador autenticado |
| secops | `/advisor/<int:plan_id>/apply` | POST | admin |
| secops | `/validations` | GET | qualquer utilizador autenticado |
| secops | `/simulations` | GET | qualquer utilizador autenticado |
| secops | `/simulations/new` | POST | admin/user |
| secops | `/autonomous` | GET,POST | qualquer utilizador autenticado |
| secops | `/autonomous/trigger` | POST | admin |
| secops | `/autonomous/<int:run_id>` | GET | qualquer utilizador autenticado |
| secops | `/autonomous/<int:run_id>/<action>` | POST | admin |
| secops | `/compliance` | GET | qualquer utilizador autenticado |
| secops | `/compliance/export.<fmt>` | GET | qualquer utilizador autenticado |
| secops | `/executive.json` | GET | qualquer utilizador autenticado |
| updates | `/updates` | GET | qualquer utilizador autenticado |
| updates | `/updates/scans` | GET | qualquer utilizador autenticado |
| updates | `/updates/scan` | POST | admin/user |
| updates | `/updates/download` | POST | admin/user |
| updates | `/updates/approve` | POST | admin/user |
| updates | `/updates/plan` | POST | admin/user |
| updates | `/updates/<int:update_id>` | GET | qualquer utilizador autenticado |

## API REST v1

Autenticação: `Authorization: Bearer omp_…` (token do perfil do utilizador); super-administradores indicam a organização em `X-Tenant-ID`.

| Método | Caminho (`/api/v1`) | Perfil | Descrição |
|---|---|---|---|
| GET | `/me` | qualquer token |  |
| GET | `/assets` | qualquer token |  |
| POST | `/assets` | admin/user |  |
| GET | `/assets/<int:asset_id>` | qualquer token |  |
| POST | `/discover` | admin |  |
| GET | `/exposures` | qualquer token |  |
| GET | `/exposures/<int:exposure_id>` | qualquer token |  |
| POST | `/correlate` | admin/user |  |
| GET | `/intel/<cve_id>` | qualquer token |  |
| POST | `/intel/import` | admin |  |
| GET | `/patches` | qualquer token |  |
| POST | `/patches` | admin/user |  |
| POST | `/patches/<int:patch_id>/approve` | admin |  |
| POST | `/patches/community` | admin |  |
| POST | `/patches/<int:patch_id>/simulate` | admin/user | Simulação prévia (sem instalar) nos ativos do âmbito: ``{"scope": {"cve_id"|"asset_ids"|"tags"}}``. |
| GET | `/preflights` | qualquer token |  |
| GET | `/sources` | qualquer token |  |
| POST | `/campaigns` | admin/user |  |
| GET | `/campaigns` | qualquer token |  |
| POST | `/signals` | admin/user |  |
| GET | `/controls` | qualquer token |  |
| POST | `/advisor` | admin/user |  |
| GET | `/autonomous` | qualquer token |  |
| POST | `/autonomous` | admin |  |
| GET | `/validations` | qualquer token |  |
| GET | `/compliance` | qualquer token |  |
| GET | `/executive` | qualquer token |  |
| POST | `/sync/omxvuln` | admin | ``{"what": "findings"|"assets"|"both", "dry_run": bool}`` — por omissão importa as vulnerabilidades. |
| POST | `/sync/omxgrc` | admin |  |
| GET | `/grc/controls` | qualquer token | Para o OMXGRC: estado de cada requisito (NIS2, ISO 27001, DORA, PCI-DSS, CIS) com métrica e estado. |
| GET | `/grc/evidence` | qualquer token | Para o OMXGRC: evidências de remediação validadas (ciclo fechado). |
| POST | `/enrollment-tokens` | admin |  |
| GET | `/practices` | qualquer token |  |
| GET | `/plans` | qualquer token |  |
| GET | `/plans/<int:plan_id>` | qualquer token |  |
| POST | `/plans` | admin/user | ``{"name", "mode": by_patch|by_asset, "asset_ids": [], "patch_ids": [], "practices": [{"id", "params"}]}``. |
| POST | `/plans/<int:plan_id>/simulate` | admin/user |  |
| POST | `/plans/<int:plan_id>/approve` | admin/user | OK explícito: exige ``"ok": true``; ``item_ids`` ou ``all_ok``; ``accept_warnings`` para itens com avisos. |
| POST | `/plans/<int:plan_id>/execute` | admin/user |  |
| GET | `/updates` | qualquer token | Atualizações pendentes. Filtros: ``asset_id``, ``source``, ``status``, ``severity``, ``category``; ``limit`` ( |
| GET | `/updates/summary` | qualquer token |  |
| GET | `/updates/scans` | qualquer token |  |
| POST | `/updates/scan` | admin/user | Pede a descoberta aos agentes: ``{"asset_ids": [..]}`` (omitido = todos). |
| POST | `/updates/download` | admin/user |  |
| GET | `/priority` | qualquer token | Exposições abertas por perda esperada (probabilidade × impacto), com a simulação de exposição. |
| GET | `/assets/<int:asset_id>/posture` | qualquer token |  |
| GET | `/baseline` | qualquer token |  |
| POST | `/plans/<int:plan_id>/change` | admin/user | Pede a *change* no ITSM (só se a gestão de changes estiver ativada; por omissão está desativada). |
| GET | `/plans/<int:plan_id>/change` | qualquer token |  |
