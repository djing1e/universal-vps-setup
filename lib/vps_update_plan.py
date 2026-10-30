#!/usr/bin/env python3
"""Offline advisory update plan from Audit JSON. Never executes update commands."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

MAX_INPUT = 4 * 1024 * 1024
CATALOG = Path(__file__).with_name('update_catalog.json')
PROTECTED = ['Docker and containers', 'Remnanode/Xray', 'Caddy/Nginx/HAProxy',
             'PostgreSQL/Redis/panel', 'SSH', 'DNS', 'routes/NetBird/WireGuard',
             'kernel', 'foreign firewall tables']


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError('duplicate JSON key')
        obj[key] = value
    return obj


def read_json(stream):
    data = stream.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError('input exceeds 4 MiB limit')
    return json.loads(data, object_pairs_hook=unique_object)


def digest_valid(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def validate_inventory(report):
    if not isinstance(report, dict):
        raise ValueError('inventory must be an object')
    if type(report.get('schema_version')) is not int or report['schema_version'] != 1:
        raise ValueError('unsupported inventory schema')
    if report.get('mode') != 'audit' or report.get('changes_applied') is not False:
        raise ValueError('require read-only Audit output')
    if report.get('update_gate') != 'manual_review_required':
        raise ValueError('unexpected inventory update gate')
    if not isinstance(report.get('os'), dict) or not isinstance(report['os'].get('properties'), dict):
        raise ValueError('invalid OS observation')
    for key in ('modules', 'services', 'probes'):
        if not isinstance(report.get(key), dict):
            raise ValueError('invalid inventory section: '+key)


def validate_catalog(catalog):
    if not isinstance(catalog, dict) or type(catalog.get('schema_version')) is not int or catalog['schema_version'] != 1:
        raise ValueError('unsupported catalog')
    if not re.fullmatch(r'[0-9a-f]{40}', catalog.get('target_revision', '')):
        raise ValueError('invalid target revision')
    components = catalog.get('components')
    if not isinstance(components, dict) or not components:
        raise ValueError('empty component catalog')
    for item in components.values():
        if not isinstance(item, dict) or not digest_valid(item.get('target_sha256')):
            raise ValueError('invalid target fingerprint')
        previous = item.get('known_previous_sha256')
        if not isinstance(previous, list) or not all(digest_valid(v) for v in previous):
            raise ValueError('invalid historical fingerprints')
        if not isinstance(item.get('path'), str) or not item['path'].startswith('/usr/local/sbin/'):
            raise ValueError('invalid component path')
        if not isinstance(item.get('units'), list) or not item['units']:
            raise ValueError('missing service prerequisites')
        if not all(isinstance(v, str) for v in item['units'] + item.get('required_probes', [])):
            raise ValueError('invalid prerequisites')


def build_plan(report, selected, catalog):
    validate_inventory(report)
    validate_catalog(catalog)
    if not selected or len(set(selected)) != len(selected):
        raise ValueError('select one or more distinct components')
    components = catalog['components']
    if any(name not in components for name in selected):
        raise ValueError('unknown component selection')
    system = report.get('os', {})
    props = system.get('properties', {}) if isinstance(system, dict) else {}
    supported_os = (system.get('status') == 'observed' and
                    (props.get('ID'), props.get('VERSION_ID')) in
                    [('debian', '13'), ('ubuntu', '24.04')]) if isinstance(props, dict) else False
    steps = []
    for name in sorted(selected):
        item = components[name]
        observed = report['modules'].get(item['path'])
        row = {'component': name, 'path': item['path'],
               'target_revision': catalog['target_revision'],
               'target_sha256': item['target_sha256'],
               'status': 'blocked', 'reasons': [], 'automatic_apply': False}
        reasons = row['reasons']
        if not supported_os:
            reasons.append('unsupported_or_unknown_os')
        for unit in item['units']:
            state = report['services'].get(unit)
            if not isinstance(state, dict) or state.get('status') != 'observed':
                reasons.append('unit_unknown_or_absent:'+unit)
                continue
            properties = state.get('properties')
            if not isinstance(properties, dict) or properties.get('LoadState') != 'loaded':
                reasons.append('unit_not_loaded:'+unit)
                continue
            # Unknown runtime state is not treated as stopped or safe to restart.
            if properties.get('ActiveState') not in ('active', 'inactive'):
                reasons.append('unit_runtime_requires_review:'+unit)
            if properties.get('UnitFileState') not in ('enabled', 'disabled', 'static', 'enabled-runtime'):
                reasons.append('unit_enablement_requires_review:'+unit)
            if not isinstance(properties.get('FragmentPath'), str) or not properties['FragmentPath'].startswith(('/etc/systemd/system/', '/usr/lib/systemd/system/', '/lib/systemd/system/')):
                reasons.append('unit_fragment_unknown:'+unit)
            if not isinstance(properties.get('DropInPaths'), str) or properties['DropInPaths']:
                reasons.append('unit_dropins_require_review:'+unit)
        for name_of_probe in item['required_probes']:
            result = report['probes'].get(name_of_probe)
            if not isinstance(result, dict) or result.get('status') != 'ok':
                reasons.append('probe_unknown:'+name_of_probe)
        if not isinstance(observed, dict):
            reasons.append('module_observation_missing')
        elif observed.get('status') == 'absent':
            reasons.append('module_absent_install_is_separate')
        elif observed.get('status') not in ('known_content', 'custom_or_unknown'):
            reasons.append('module_unknown')
        else:
            current = observed.get('sha256')
            if not digest_valid(current):
                reasons.append('invalid_current_fingerprint')
            elif current not in [item['target_sha256']] + item['known_previous_sha256']:
                reasons.append('unrecognized_content')
            else:
                row['current_sha256'] = current
                if not reasons:
                    if current == item['target_sha256']:
                        row['status'] = 'noop'
                        reasons.append('target_content_already_present')
                    else:
                        row['status'] = 'review_required'
                        reasons.extend(['known_previous_content', 'ownership_not_established',
                                        'backup_and_rollback_not_implemented', 'fresh_audit_required_before_apply'])
        steps.append(row)
    counts = {status: sum(row['status'] == status for row in steps)
              for status in ('noop', 'review_required', 'blocked')}
    return {'schema_version': 1, 'mode': 'plan', 'changes_applied': False,
            'apply_available': False, 'update_gate': 'manual_review_required',
            'inventory_digest': hashlib.sha256(json.dumps(report, sort_keys=True,
                                                         separators=(',', ':')).encode()).hexdigest(),
            'target_revision': catalog['target_revision'], 'summary': counts,
            'steps': steps, 'protected_resources': PROTECTED,
            'limitations': ['Advisory plan only; no downloads, commands, backups, restarts or writes.',
                            'Known content does not establish ownership or authorize replacement.',
                            'A noop concerns selected executable content, not service health or configuration.',
                            'Inventory freshness and host binding are not established; this plan cannot be applied.']}


def render_text(plan):
    lines = ['VPS update plan — advisory only; changes applied: no',
             'Target revision: '+plan['target_revision']]
    for row in plan['steps']:
        lines.append(row['component']+': '+row['status'])
        lines.extend('  '+reason for reason in row['reasons'])
    lines.append('Apply is unavailable. Existing service states and configuration must be preserved.')
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', required=True, help='Audit JSON file, or - for stdin')
    parser.add_argument('--select', nargs='+', required=True,
                        choices=['tcp-c2', 'spamhaus-output', 'auto-abuse-guard'])
    parser.add_argument('--format', choices=['text', 'json'], default='text')
    args = parser.parse_args()
    try:
        if args.inventory == '-':
            report = read_json(sys.stdin.buffer)
        else:
            with open(args.inventory, 'rb') as stream:
                report = read_json(stream)
        with CATALOG.open('rb') as stream:
            catalog = read_json(stream)
        plan = build_plan(report, args.select, catalog)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        parser.exit(2, 'Plan refused: '+str(exc)+'\n')
    print(json.dumps(plan, ensure_ascii=False, indent=2) if args.format == 'json' else render_text(plan))


if __name__ == '__main__':
    main()
