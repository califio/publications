#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_dir="$(cd "${script_dir}/.." && pwd)"
compose=(docker compose -f "${release_dir}/docker-compose.yml")

echo "[*] Starting vulnerable Apache/mod_php lab"
"${compose[@]}" up -d --build db wordpress wpcli

echo "[*] Waiting for Apache/PHP health endpoint"
for _ in $(seq 1 60); do
	if curl -fsS http://127.0.0.1:8083/__apache-health.php >/tmp/wp2shell-apache81-health.json 2>/dev/null; then
		break
	fi
	sleep 2
done

if ! curl -fsS http://127.0.0.1:8083/__apache-health.php >/tmp/wp2shell-apache81-health.json 2>/dev/null; then
	echo "[-] Apache/PHP health endpoint did not become ready" >&2
	exit 1
fi

echo "[*] Installing WordPress 7.0.1 if needed"
if ! "${compose[@]}" exec -T wpcli wp core is-installed >/dev/null 2>&1; then
	"${compose[@]}" exec -T wpcli wp core install \
		--url="http://localhost:8083" \
		--title="WP2Shell Apache 8.1 Lab" \
		--admin_user="admin" \
		--admin_password="SuperSecret123!" \
		--admin_email="admin@example.com" \
		--skip-email
fi

echo "[*] Runtime: $(cat /tmp/wp2shell-apache81-health.json)"
echo -n "[*] Core: "
"${compose[@]}" exec -T wpcli wp core version
echo "[+] READY: http://localhost:8083/"
echo "    login: admin / SuperSecret123!"
