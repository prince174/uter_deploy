"""Conservative TCP inventory parser, not an ingress fence or authorization.

Input must come from a trusted, pinned `ss -H -n -t -a` in an authenticated
container network namespace. This function does not execute ss, pin a namespace,
check rules or peer identities, prevent restart, or cover UDP and Unix sockets.
Do not use its result alone to allow maintenance or an update.
"""
import ipaddress
import re


class SocketInventoryError(ValueError):
    pass


_STATE = frozenset(('LISTEN','ESTAB','SYN-SENT','SYN-RECV','FIN-WAIT-1',
                    'FIN-WAIT-2','TIME-WAIT','CLOSE-WAIT','LAST-ACK','CLOSING','CLOSE'))


def _endpoint(raw, *, wildcard=False):
    # Reject scoped IPv6 and ambiguous text rather than guessing its meaning.
    if '%' in raw or ':' not in raw: raise ValueError
    address, port = raw.rsplit(':', 1)
    if address.startswith('[') and address.endswith(']'): address=address[1:-1]
    if address == '*':
        if not wildcard: raise ValueError
        ip=None
    else:
        ip=ipaddress.ip_address(address)
        if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            raise ValueError
    if port == '*':
        if not wildcard: raise ValueError
        number=None
    else:
        if not re.fullmatch(r'[0-9]{1,5}',port):raise ValueError
        number=int(port)
        if not 0 <= number <= 65535:raise ValueError
    return ip,number


def inspect(raw, *, port, service_addresses, peer_addresses):
    """Reject unknown listeners and active external inbound connections.

    The narrowly allowed peer addresses must already be authenticated by the
    caller and continuously protected from spoofing. Output is only a check of
    one socket snapshot; TIME-WAIT is conservatively treated as active.
    """
    try:
        if (not isinstance(raw, bytes) or len(raw)>262144
                or type(port) is not int or not 1 <= port <= 65535
                or not isinstance(peer_addresses, (tuple,list)) or not 1 <= len(peer_addresses) <= 2
                or not isinstance(service_addresses, (tuple,list)) or len(service_addresses)!=len(peer_addresses)):raise ValueError
        peers={ipaddress.IPv4Address(x) for x in peer_addresses}
        local_ips={ipaddress.IPv4Address(x) for x in service_addresses}
        if (len(peers)!=len(peer_addresses) or len(local_ips)!=len(service_addresses) or peers & local_ips
                or any(x.is_loopback or x.is_unspecified or x.is_multicast for x in peers | local_ips)):raise ValueError
        matched=dict(zip(map(ipaddress.IPv4Address,service_addresses),map(ipaddress.IPv4Address,peer_addresses)))
        listeners=0
        lines=raw.decode('ascii').splitlines()
        if len(lines)>4096:raise ValueError
        for line in lines:
            if len(line)>512:raise ValueError
            fields=line.split()
            if len(fields)!=5 or fields[0] not in _STATE or any(not re.fullmatch(r'[0-9]+',x) for x in fields[1:3]):
                raise ValueError
            state=fields[0];local,local_port=_endpoint(fields[3],wildcard=state=='LISTEN')
            remote,remote_port=_endpoint(fields[4],wildcard=state=='LISTEN')
            if state=='LISTEN':
                # A wildcard IPv6 listener would need its own independently
                # installed and verified ip6tables fence. Reject it for now.
                if local_port!=port or local is None or isinstance(local,ipaddress.IPv6Address):raise ValueError
                if not (local.is_unspecified or local.is_loopback or local in local_ips):raise ValueError
                if int(fields[1])!=0 or remote_port is not None or (remote is not None and not remote.is_unspecified):raise ValueError
                listeners+=1
            elif local_port==port:
                if local is None or remote is None or remote_port is None:raise ValueError
                if not (remote.is_loopback and local.is_loopback) and matched.get(local)!=remote:raise ValueError
        if listeners != 1:raise ValueError
        return True
    except Exception:
        raise SocketInventoryError('COMPOSE_INGRESS_SOCKETS_UNVERIFIED') from None
