#!/bin/sh
# Minimal Heimdal KDC for CI integration tests. Realm HEIMDAL.TEST with a
# password user and a service principal. Enctypes: AES256/AES128/DES3/RC4.
set -e
kstash --random-key >/dev/null
kadmin -l init --realm-max-ticket-life=unlimited --realm-max-renewable-life=unlimited HEIMDAL.TEST
kadmin -l add --password='Passw0rd!1' --use-defaults victim
kadmin -l add --random-key --use-defaults host/svc.heimdal.test
exec /usr/lib/heimdal-servers/kdc --config-file=/etc/heimdal-kdc/kdc.conf
