#!/usr/bin/env bash
# =====================================================================================================
#  OMXPatch — instalação automática em Ubuntu Server 24.04 / 26.04 (ou Debian) — centro de comando.
#
#  Instala: utilizador de sistema "omxpatch", /opt/omxpatch (ambiente virtual + aplicação), /etc/omxpatch
#  (configuração), /var/lib/omxpatch (dados), serviços systemd (web + worker) e abre as portas no ufw:
#    4434/tcp  consola de gestão   (https://omxpatch.oramix.local:4434)   certificado autoassinado, 2 anos
#    4444/tcp  agentes → consola   (https://omxpatchcli.oramix.local:4444) certificado autoassinado, 2 anos
#
#  Uso (como root, na pasta extraída do pacote):
#    sudo ./install.sh
#    sudo ./install.sh --hostname omxpatch.empresa.pt --agent-hostname omxpatchcli.empresa.pt --server-ip 10.0.0.5
#    sudo ./install.sh --with-ansible            # ansible-core + WinRM (modo sem agente, descoberta Hyper-V)
#  Pode ser executado de novo para atualizar: a configuração e os dados são mantidos.
#  Registo: /var/log/omxpatch-install.log
# =====================================================================================================
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
FQDN="omxpatch.oramix.local"; AGENT_FQDN="omxpatchcli.oramix.local"; SERVER_IP=""
PORT=4434; AGENT_PORT=4444; WITH_ANSIBLE=0; FIREWALL=1
APP="${OMXPATCH_APP:-/opt/omxpatch}"; ETC="${OMXPATCH_ETC:-/etc/omxpatch}"; DATA="${OMXPATCH_DATA:-/var/lib/omxpatch}"
UNITDIR="${OMXPATCH_UNITDIR:-/etc/systemd/system}"; SVC_USER=omxpatch; LOG="${OMXPATCH_LOG:-/var/log/omxpatch-install.log}"
NO_SERVICE=0; NO_APT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --hostname) FQDN="$2"; shift 2 ;;
    --agent-hostname) AGENT_FQDN="$2"; shift 2 ;;
    --server-ip) SERVER_IP="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --agent-port) AGENT_PORT="$2"; shift 2 ;;
    --with-ansible) WITH_ANSIBLE=1; shift ;;
    --no-firewall) FIREWALL=0; shift ;;
    --no-service) NO_SERVICE=1; shift ;;      # testes / contentores
    --no-apt) NO_APT=1; shift ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Opção desconhecida: $1" >&2; exit 2 ;;
  esac
done
[ "$(id -u)" = 0 ] || { echo "Execute como root: sudo $0" >&2; exit 1; }
for v in "$FQDN" "$AGENT_FQDN"; do case "$v" in *[!A-Za-z0-9.-]*|"") echo "Nome inválido: $v" >&2; exit 1 ;; esac; done
for v in "$PORT" "$AGENT_PORT"; do case "$v" in *[!0-9]*|"") echo "Porta inválida: $v" >&2; exit 1 ;; esac; done
case "$SERVER_IP" in *[!0-9a-fA-F:.]*) echo "IP inválido" >&2; exit 1 ;; esac
ls "$HERE"/wheels/omxpatch-*.whl >/dev/null 2>&1 || { echo "Pacote incompleto: faltam os wheels em $HERE/wheels" >&2; exit 1; }

touch "$LOG"; chmod 600 "$LOG"; exec > >(tee -a "$LOG") 2>&1
step() { printf '\n\033[1;34m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33mAVISO:\033[0m %s\n' "$*"; }
HAS_SYSTEMD=0; [ -d /run/systemd/system ] && [ "$NO_SERVICE" = 0 ] && HAS_SYSTEMD=1
echo "OMXPatch $(cat "$HERE/VERSION" 2>/dev/null || echo '?') — $(date)"

step "Pacotes do sistema"
have_py() { command -v python3 >/dev/null && python3 -c 'import sys; assert sys.version_info >= (3, 9)' 2>/dev/null; }
have_venv() { have_py && python3 -c 'import venv, ensurepip' 2>/dev/null; }
if [ "$NO_APT" = 0 ] && command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  # Python, venv e pip (o Ubuntu Server traz o python3 mas não o python3-venv/pip)
  if apt-get update -qq && apt-get install -y -qq python3 python3-venv python3-pip ca-certificates openssl openssh-client sshpass; then :; else
    warn "apt indisponível ou incompleto."
  fi
fi
if ! have_venv && ls "$HERE"/debs/*.deb >/dev/null 2>&1; then
  warn "A instalar Python/venv/pip a partir dos pacotes incluídos (debs/)."
  dpkg -i --skip-same-version "$HERE"/debs/*.deb || apt-get install -y -qq -f || true
fi
have_py || { echo "Python ≥ 3.9 não encontrado e não foi possível instalá-lo (apt sem rede e sem debs/ compatíveis com esta versão do Ubuntu)." >&2; exit 1; }
have_venv || { echo "Falta o módulo venv/ensurepip: instale 'python3-venv python3-pip' (sudo apt install python3-venv python3-pip) e repita." >&2; exit 1; }

step "Utilizador e diretórios"
id "$SVC_USER" >/dev/null 2>&1 || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin "$SVC_USER"
mkdir -p "$APP" "$ETC" "$DATA"
chown -R "$SVC_USER":"$SVC_USER" "$DATA"; chmod 750 "$DATA"; chmod 755 "$APP"; chgrp "$SVC_USER" "$ETC"; chmod 750 "$ETC"

step "Aplicação (ambiente virtual)"
PREV="$("$APP/venv/bin/pip" show omxpatch 2>/dev/null | sed -n 's/^Version: //p' || true)"
python3 -m venv "$APP/venv"
PIP="$APP/venv/bin/pip"
if [ -n "$PREV" ]; then echo "Versão instalada: $PREV  ->  versão do pacote: $(cat "$HERE/VERSION" 2>/dev/null || echo '?')"; else echo "Instalação nova (versão do pacote: $(cat "$HERE/VERSION" 2>/dev/null || echo '?'))"; fi
"$PIP" install -q --upgrade pip >/dev/null 2>&1 || true
if ! "$PIP" install -q --upgrade --no-index --find-links "$HERE/wheels" omxpatch; then
  warn "Instalação offline incompatível com este Python; a usar o PyPI."
  "$PIP" install -q --upgrade --find-links "$HERE/wheels" omxpatch
fi
echo "Versão instalada agora: $("$PIP" show omxpatch | sed -n 's/^Version: //p')"
if [ "$WITH_ANSIBLE" = 1 ]; then
  step "Ansible (modo sem agente)"
  "$PIP" install -q ansible-core pywinrm requests-credssp jmespath
  "$APP/venv/bin/ansible-galaxy" collection install ansible.posix community.general ansible.windows community.windows \
      -p "$APP/venv/share/omxpatch/ansible/collections" || warn "Coleções Ansible não instaladas (sem acesso ao Galaxy?)."
fi

step "Configuração"
if [ ! -f "$ETC/omxpatch.toml" ]; then
  cat > "$ETC/omxpatch.toml" <<TOML
# Gerado pelo instalador. Ver omxpatch.toml.example na documentação.
data_dir = "$DATA"

[server]
tls_enabled = true
tls_hostname = "$FQDN"              # certificado da consola (porta $PORT)
port = $PORT
session_cookie_secure = true
embedded_worker = false             # o worker corre como serviço próprio

[agents]
tls_hostname = "$AGENT_FQDN"        # certificado dos agentes (porta $AGENT_PORT)
port = $AGENT_PORT
server_ip = "$SERVER_IP"            # os scripts de instalação dos agentes acrescentam-no ao ficheiro hosts

[ansible]
enabled = $([ "$WITH_ANSIBLE" = 1 ] && echo true || echo false)
playbook = "$APP/venv/bin/ansible-playbook"
TOML
  chown root:"$SVC_USER" "$ETC/omxpatch.toml"; chmod 640 "$ETC/omxpatch.toml"
else
  echo "Configuração existente mantida: $ETC/omxpatch.toml"
fi
cp "$HERE/uninstall.sh" "$APP/uninstall.sh" 2>/dev/null && chmod 755 "$APP/uninstall.sh" || true

step "Certificados TLS (autoassinados, 2 anos)"
export OMXPATCH_CONFIG="$ETC/omxpatch.toml"
if [ "$(id -u "$SVC_USER")" != 0 ]; then
  runuser -u "$SVC_USER" -- env OMXPATCH_CONFIG="$ETC/omxpatch.toml" "$APP/venv/bin/omxpatch" tls info || warn "Falha ao gerar os certificados"
fi

if [ "$HAS_SYSTEMD" = 1 ]; then
  step "Serviços systemd"
  cat > "$UNITDIR/omxpatch.service" <<UNIT
[Unit]
Description=OMXPatch — centro de comando (consola $PORT / agentes $AGENT_PORT)
After=network-online.target
Wants=network-online.target

[Service]
User=$SVC_USER
Environment=OMXPATCH_CONFIG=$ETC/omxpatch.toml
Environment=ANSIBLE_COLLECTIONS_PATH=$APP/venv/share/omxpatch/ansible/collections
ExecStart=$APP/venv/bin/omxpatch serve --no-worker
Restart=always
RestartSec=5
NoNewPrivileges=true
ProtectSystem=full
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
  cat > "$UNITDIR/omxpatch-worker.service" <<UNIT
[Unit]
Description=OMXPatch — worker (correlação, campanhas, anéis, validação, Ansible)
After=omxpatch.service

[Service]
User=$SVC_USER
Environment=OMXPATCH_CONFIG=$ETC/omxpatch.toml
Environment=ANSIBLE_COLLECTIONS_PATH=$APP/venv/share/omxpatch/ansible/collections
ExecStart=$APP/venv/bin/omxpatch worker
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable omxpatch omxpatch-worker >/dev/null
  systemctl restart omxpatch omxpatch-worker
  for i in $(seq 1 30); do
    curl -ksf "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && break; sleep 1
  done
  curl -ksf "https://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && echo "Consola a responder em :$PORT — versão em execução: $(curl -ksf "https://127.0.0.1:$PORT/healthz" | sed -n 's/.*"version": *"\([^"]*\)".*/\1/p')" || warn "A consola ainda não responde: journalctl -u omxpatch"
else
  warn "systemd indisponível (ou --no-service): serviços não instalados. Arranque manual: OMXPATCH_CONFIG=$ETC/omxpatch.toml $APP/venv/bin/omxpatch serve"
fi

if [ "$FIREWALL" = 1 ] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  step "Firewall (ufw)"
  ufw allow "$PORT"/tcp comment 'OMXPatch consola' >/dev/null; ufw allow "$AGENT_PORT"/tcp comment 'OMXPatch agentes' >/dev/null
fi

step "Super-administrador inicial"
if [ "$(id -u "$SVC_USER")" != 0 ]; then
  runuser -u "$SVC_USER" -- env OMXPATCH_CONFIG="$ETC/omxpatch.toml" "$APP/venv/bin/omxpatch" initial-password || true
fi
cat <<EOF

Concluído.
  Consola:  https://$FQDN:$PORT/            (nome a resolver por DNS ou ficheiro hosts)
  Agentes:  https://$AGENT_FQDN:$AGENT_PORT/  (usado pelos scripts de instalação dos agentes)
  Passos seguintes: criar a organização (Organizações), e em «Agentes» gerar os scripts de auto-instalação.
EOF
