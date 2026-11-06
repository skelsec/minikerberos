#!/bin/sh
# Minimal MIT KDC for CI integration tests. Realm MIT.TEST with a password
# user and a service principal. Enctypes: AES256/AES128/DES3/RC4.
set -e
kdb5_util create -s -r MIT.TEST -P masterpw >/dev/null
kadmin.local -q "addprinc -pw Passw0rd!1 victim" >/dev/null
kadmin.local -q "addprinc -randkey host/svc.mit.test" >/dev/null
exec krb5kdc -n
