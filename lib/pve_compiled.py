"""Conservative offline checks of PVE compiler output, never packet reachability proof."""
import ipaddress
import re
import shlex

PROTECTED = (22, 8006, 3128, *range(5900, 6000), *range(60000, 60051))


def expected_rules(text):
    sections = text.split('[RULES]')
    if len(sections) != 2:
        raise ValueError('exactly one candidate RULES section required')
    result = []
    for raw in sections[1].splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        match = re.fullmatch(r'IN ACCEPT -source (\S+) -p tcp -dport (22|8006|3128)', line)
        if not match:
            raise ValueError('candidate rule outside supported semantic grammar: '+line)
        network = ipaddress.ip_network(match[1], strict=True)
        result.append((network.version, str(network), 'tcp', int(match[2])))
    if not result or len(result) != len(set(result)):
        raise ValueError('candidate has empty or duplicate rules')
    return result


def tokens(rule, chain):
    if not isinstance(rule, str):
        raise ValueError('unsupported compiled rule representation')
    parts = shlex.split(rule)
    if parts[:2] != ['-A', chain]:
        raise ValueError('compiled chain/rule mismatch')
    return parts[2:]


def value(parts, option, default=None):
    if option not in parts:
        return default
    if parts.count(option) != 1 or parts.index(option) + 1 >= len(parts):
        raise ValueError('ambiguous compiled option '+option)
    return parts[parts.index(option)+1]


def semantic_match(parts):
    """Only an exact supported host rule counts, not a substring in another chain."""
    allowed = {'-s': 1, '-p': 1, '--dport': 1, '-j': 1, '-m': 1}
    i = 0
    while i < len(parts):
        option = parts[i]
        if option not in allowed or i+1 >= len(parts):
            return None
        if option == '-m' and parts[i+1] != 'tcp':
            return None
        i += 2
    source = value(parts, '-s')
    if not source or value(parts, '-p') != 'tcp' or value(parts, '-j') != 'RETURN':
        return None
    try:
        network = ipaddress.ip_network(source, strict=True)
        port = int(value(parts, '--dport'))
    except (ValueError, TypeError):
        return None
    return network.version, str(network), 'tcp', port


def management_set(snapshot, family):
    name = f'PVEFW-0-management-v{family}'
    raw = snapshot['ipsets'].get(name)
    result = {'name': name, 'members': [], 'unknown': False}
    if not isinstance(raw, list) or not raw:
        return dict(result, unknown=True)
    created = False
    for line in raw:
        parts = shlex.split(line)
        if (len(parts) >= 6 and parts[:4] == ['create', name, 'hash:net', 'family']
                and parts[4] == ('inet' if family == 4 else 'inet6')):
            if created:
                result['unknown'] = True
            created = True
        elif len(parts) == 3 and parts[:2] == ['add', name]:
            try:
                network = ipaddress.ip_network(parts[2], strict=True)
                if network.version != family:
                    raise ValueError('family mismatch')
                result['members'].append(str(network))
            except ValueError:
                result['unknown'] = True
        else:
            # nomatch, nested sets, unknown syntax: no optimistic inference.
            result['unknown'] = True
    result['unknown'] |= not created
    return result


def analyze(snapshot, expected):
    if not isinstance(snapshot, dict) or snapshot.get('schema_version') != 1:
        raise ValueError('unsupported compiler snapshot schema')
    if not isinstance(snapshot.get('ipsets'), dict):
        raise ValueError('compiled ipsets missing')
    admins = {family: [ipaddress.ip_network(source) for f, source, _, _ in expected if f == family]
              for family in (4, 6)}
    missing = []; risks = []; graphs = {}; sets = {}
    for family in (4, 6):
        chains = snapshot.get('ipv'+str(family))
        if not isinstance(chains, dict) or 'PVEFW-HOST-IN' not in chains:
            raise ValueError('compiled IPv%d Host chain missing' % family)
        if len(chains) > 2048 or any(not isinstance(rows, list) for rows in chains.values()):
            raise ValueError('unsupported or oversized chain map')
        parsed = {name: [tokens(rule, name) for rule in rows] for name, rows in chains.items()}
        matches = {semantic_match(parts) for parts in parsed['PVEFW-HOST-IN']}
        missing += [list(rule) for rule in expected if rule[0] == family and rule not in matches]
        sets[str(family)] = management_set(snapshot, family)
        # Walk reachable calls in compiler order. RETURN is reported with caller
        # continuation; it is never promoted to final ACCEPT or proof of access.
        root = 'INPUT' if 'INPUT' in chains else 'PVEFW-INPUT'
        edges = []; visited = set()
        def visit(chain, stack):
            if len(stack) > 64 or chain in stack:
                risks.append({'family': family, 'reason': 'cycle/depth in input graph', 'chain': chain})
                return
            if chain in visited:
                return
            visited.add(chain)
            for index, parts in enumerate(parsed.get(chain, [])):
                target = value(parts, '-j')
                if '-g' in parts:
                    risks.append({'family': family, 'chain': chain, 'index': index, 'reason': 'unsupported goto'})
                if target in chains:
                    edges.append({'caller': chain, 'index': index, 'callee': target,
                                  'continuation_index': index+1})
                    visit(target, stack+[chain])
                    continue
                if target not in ('ACCEPT', 'RETURN'):
                    if target not in ('DROP', 'REJECT', 'NFLOG', 'LOG'):
                        risks.append({'family': family, 'chain': chain, 'index': index, 'reason': 'unknown target'})
                    continue
                protocol = value(parts, '-p')
                if '!' not in parts and protocol in ('icmp', 'ipv6-icmp', 'icmpv6', 'igmp', 'udp'):
                    continue
                states = value(parts, '--ctstate', '')
                if '!' not in parts and states and set(states.split(',')) <= {'ESTABLISHED', 'RELATED'}:
                    continue
                if '!' not in parts and value(parts, '-i') == 'lo':
                    continue
                port_text = value(parts, '--dport')
                ports = set(PROTECTED)
                if port_text and '!' not in parts:
                    try:
                        bounds = [int(v) for v in port_text.split(':')]
                        if len(bounds) not in (1, 2) or not all(1 <= v <= 65535 for v in bounds):
                            raise ValueError('port syntax')
                        if len(bounds) == 2 and bounds[0] > bounds[1]:
                            raise ValueError('reversed port range')
                        ports &= set(range(bounds[0], bounds[-1]+1))
                    except ValueError:
                        pass  # Unknown positive match remains a potential opening.
                if not ports:
                    continue
                sources = None
                if '--match-set' in parts:
                    name = value(parts, '--match-set')
                    at = parts.index('--match-set')
                    if '!' not in parts and name == sets[str(family)]['name'] and parts[at+2:at+3] == ['src'] and not sets[str(family)]['unknown']:
                        sources = sets[str(family)]['members']
                elif '-s' in parts and '!' not in parts:
                    sources = [value(parts, '-s')]
                try:
                    restricted = sources is not None and all(
                        ipaddress.ip_network(source).version == family and any(
                            ipaddress.ip_network(source).subnet_of(admin) for admin in admins[family])
                        for source in sources)
                except ValueError:
                    restricted = False
                if not restricted or any(port not in {r[3] for r in expected if r[0] == family} for port in ports):
                    risks.append({'family': family, 'chain': chain, 'index': index, 'target': target,
                                  'ports': sorted(ports), 'sources': sources,
                                  'reason': 'potential management path outside requested scope',
                                  'terminal_accept_in_this_chain': target == 'ACCEPT',
                                  'return_requires_caller_continuation': target == 'RETURN'})
        if root not in parsed:
            risks.append({'family': family, 'reason': 'input entry chain missing'})
        else:
            visit(root, [])
        graphs[str(family)] = {'entry': root, 'ordered_calls': edges, 'visited': sorted(visited),
                               'kernel_input_hook_verified': False,
                               'analysis_kind': 'conservative_structure_not_symbolic_packet_execution'}
    return {'semantic_rules_verified': not missing, 'missing_rules': missing,
            'management_sets': sets, 'input_graphs': graphs, 'potential_openings': risks,
            'management_access_verified': False, 'activation_allowed': False,
            'limitations': ['Compiler output is not the live complete INPUT pipeline.',
                           'Conservative graph inspection is not packet simulation; RETURN is not ACCEPT.',
                           'Unknown matches, hooks and caller policies preclude activation.']}
