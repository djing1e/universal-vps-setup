#!/usr/bin/env python3
"""Explicit registration of a pinned Guard release; never installs or updates it."""
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

CATALOG = Path(__file__).with_name('module_releases.json')
COMPONENT = 'auto-abuse-guard'
RESOURCES = (
    '/usr/local/sbin/xtls-auto-abuse-guard',
    '/etc/systemd/system/xtls-auto-abuse-guard.service',
    '/etc/systemd/system/xtls-auto-abuse-guard.timer',
)
RECEIPT = '/var/lib/xtls-vps-manager/components/auto-abuse-guard.json'
CONFIRM = 'ADOPT-AUTO-ABUSE-GUARD'


def read_regular(path, limit):
    for part in (path,*path.parents):
        if part.is_symlink(): raise ValueError('symlink_requires_review')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError('not_an_independent_regular_file')
        if info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError('untrusted_file_metadata')
        raw = stream.read(limit+1)
    if len(raw)>limit: raise ValueError('file_too_large')
    return raw, {'sha256':hashlib.sha256(raw).hexdigest(),'uid':info.st_uid,
                 'gid':info.st_gid,'mode':stat.S_IMODE(info.st_mode)}


def validate_catalog(catalog):
    if not isinstance(catalog,dict) or type(catalog.get('schema_version')) is not int or catalog['schema_version']!=1:
        raise ValueError('unsupported_release_catalog')
    components = catalog.get('components')
    if not isinstance(components,dict): raise ValueError('invalid_components')
    item = components.get(COMPONENT)
    if not isinstance(item,dict) or not re.fullmatch(r'\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?',item.get('version','')):
        raise ValueError('invalid_release_version')
    if not re.fullmatch(r'[0-9a-f]{40}',item.get('source_revision','')):
        raise ValueError('invalid_release_revision')
    resources = item.get('resources')
    if not isinstance(resources,dict) or set(resources)!=set(RESOURCES):
        raise ValueError('unexpected_resource_paths')
    for spec in resources.values():
        if not isinstance(spec,dict) or not re.fullmatch(r'[0-9a-f]{64}',spec.get('sha256','')):
            raise ValueError('invalid_resource_hash')
        modes = spec.get('allowed_modes')
        if not isinstance(modes,list) or not modes or not all(type(m) is int and m in (0o600,0o644,0o755) for m in modes):
            raise ValueError('invalid_resource_modes')
    return item


def unique_json(raw):
    def object_pairs(pairs):
        obj = {}
        for key,value in pairs:
            if key in obj: raise ValueError('duplicate_json_key')
            obj[key] = value
        return obj
    return json.loads(raw,object_pairs_hook=object_pairs)


def load_catalog():
    return unique_json(CATALOG.read_text())


def inspect(root=Path('/'), catalog=None, receipt_path=None):
    release = validate_catalog(load_catalog() if catalog is None else catalog)
    resources = {}
    for name,spec in release['resources'].items():
        try:
            _, metadata = read_regular(root/name.lstrip('/'),2*1024*1024)
            match = metadata['sha256']==spec['sha256'] and metadata['mode'] in spec['allowed_modes']
            resources[name] = dict(metadata,status='matches_release' if match else 'drift')
        except FileNotFoundError:
            resources[name] = {'status':'absent'}
        except (OSError,ValueError):
            resources[name] = {'status':'unknown'}
    recognized = all(r['status']=='matches_release' for r in resources.values())
    result = {'component':COMPONENT,'status':'recognized_unregistered' if recognized else 'unknown',
              'detected_version':release['version'] if recognized else None,
              'ownership':'not_established','resources':resources,
              'changes_applied':False,'automatic_update':False}
    path = receipt_path if receipt_path is not None else root/RECEIPT.lstrip('/')
    try:
        raw, metadata = read_regular(path,16384)
        if metadata['mode']!=0o600: raise ValueError('unsafe_receipt_mode')
        for directory in (path.parent,path.parent.parent):
            info = directory.stat()
            if info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
                raise ValueError('unsafe_registry_directory')
        receipt = unique_json(raw)
        expected_keys={'schema_version','component','version','source_revision','registered_at','provenance','resources'}
        if not isinstance(receipt,dict) or set(receipt)!=expected_keys or type(receipt['schema_version']) is not int or receipt['schema_version']!=1:
            raise ValueError('invalid_receipt_schema')
        if (receipt['component']!=COMPONENT or receipt['version']!=release['version'] or
                receipt['source_revision']!=release['source_revision'] or receipt['provenance'] not in ('explicit_adoption','managed_install','managed_update')):
            raise ValueError('unrecognized_receipt_release')
        timestamp = dt.datetime.fromisoformat(receipt['registered_at'])
        if timestamp.tzinfo is None: raise ValueError('receipt_time_requires_timezone')
        recorded = receipt['resources']
        if not isinstance(recorded,dict) or set(recorded)!=set(RESOURCES):
            raise ValueError('invalid_receipt_resources')
        for name,item in recorded.items():
            spec = release['resources'][name]
            if (not isinstance(item,dict) or set(item)!={'sha256','uid','gid','mode'} or
                    item['sha256']!=spec['sha256'] or type(item['uid']) is not int or type(item['gid']) is not int or item['uid']!=0 or item['gid']!=0 or
                    type(item['mode']) is not int or item['mode'] not in spec['allowed_modes']):
                raise ValueError('invalid_recorded_resource')
        current = {name:{key:value for key,value in item.items() if key!='status'} for name,item in resources.items()}
        result.update(status='registered_matches' if recognized and current==recorded else 'registered_drift',
                      recorded_version=receipt['version'],ownership='explicitly_recorded',
                      registered_at=receipt['registered_at'])
    except FileNotFoundError:
        pass
    except (OSError,ValueError,TypeError,KeyError):
        result.update(status='unknown',reason='receipt_requires_review')
    return result


def verify_units(runner):
    for name in ('xtls-auto-abuse-guard.service','xtls-auto-abuse-guard.timer'):
        result = runner(['systemctl','show','--no-pager',name,
                         '--property=LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,NeedDaemonReload'])
        if result.get('status')!='ok': raise ValueError('unit_probe_unknown: '+name)
        props = dict(line.split('=',1) for line in result.get('output','').splitlines() if '=' in line)
        allowed = ('active','inactive') if name.endswith('.timer') else ('active','inactive','activating')
        enablement = ('enabled','disabled') if name.endswith('.timer') else ('enabled','disabled','static')
        if (props.get('LoadState')!='loaded' or props.get('FragmentPath')!='/etc/systemd/system/'+name or
                props.get('DropInPaths')!='' or props.get('NeedDaemonReload')!='no' or
                props.get('ActiveState') not in allowed or not props.get('SubState') or
                props.get('UnitFileState') not in enablement):
            raise ValueError('unit_requires_review: '+name)


def adopt(root=Path('/'),catalog=None,runner=None):
    if os.geteuid()!=0: raise ValueError('root_required')
    if runner is None:
        from vps_inventory import probe
        runner = probe
    catalog = load_catalog() if catalog is None else catalog
    release = validate_catalog(catalog)
    lockpath = root/'run/xtls-auto-abuse-guard-install.lock'
    fd = os.open(lockpath,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    with os.fdopen(fd,'a') as lock:
        info = os.fstat(lock.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or info.st_nlink!=1:
            raise ValueError('unsafe_installer_lock')
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        result = inspect(root,catalog)
        if result['status'] not in ('recognized_unregistered','registered_matches'):
            raise ValueError('resources_or_receipt_require_review')
        verify_units(runner)
        if result['status']=='registered_matches': return result
        record = {'schema_version':1,'component':COMPONENT,'version':release['version'],
                  'source_revision':release['source_revision'],'provenance':'explicit_adoption',
                  'registered_at':dt.datetime.now(dt.timezone.utc).isoformat(),
                  'resources':{name:{key:value for key,value in item.items() if key!='status'}
                               for name,item in result['resources'].items()}}
        destination = root/RECEIPT.lstrip('/')
        for path in (root/'var/lib/xtls-vps-manager',destination.parent):
            if path.is_symlink(): raise ValueError('registry_symlink_requires_review')
            path.mkdir(mode=0o700,exist_ok=True)
            info = path.stat()
            if info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
                raise ValueError('unsafe_registry_directory')
        fd, temporary = tempfile.mkstemp(prefix='.adopt-',dir=destination.parent)
        try:
            with os.fdopen(fd,'wb') as stream:
                os.fchown(stream.fileno(),0,0);os.fchmod(stream.fileno(),0o600)
                stream.write(json.dumps(record,indent=2).encode()+b'\n')
                stream.flush();os.fsync(stream.fileno())
            # Atomic create without replacing even a concurrently created receipt.
            os.link(temporary,destination,follow_symlinks=False)
        finally:
            Path(temporary).unlink(missing_ok=True)
        directory = os.open(destination.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)
        updated = inspect(root,catalog)
        if updated['status']!='registered_matches': raise ValueError('registration_verification_failed')
        updated['changes_applied']=True
        return updated


class Registration:
    """Receipt operations for a caller holding the shared installer lock."""
    def __init__(self, root=Path('/'), catalog=None, receipt_path=None):
        self.root = root
        self.catalog = load_catalog() if catalog is None else catalog
        self.release = validate_catalog(self.catalog)
        self.path = receipt_path if receipt_path is not None else root/RECEIPT.lstrip('/')

    def current(self):
        try:
            raw, metadata = read_regular(self.path,16384)
            if metadata['mode']!=0o600: raise ValueError('unsafe_receipt_mode')
            return raw
        except FileNotFoundError:
            return None

    def validate_storage(self):
        for directory in (self.path.parent.parent,self.path.parent):
            if directory.is_symlink(): raise ValueError('registry_symlink_requires_review')
            if directory.exists():
                info=directory.stat()
                if info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
                    raise ValueError('unsafe_registry_directory')

    def snapshot(self):
        self.validate_storage()
        raw = self.current()
        if raw is not None and inspect(self.root,self.catalog,self.path)['status']!='registered_matches':
            raise ValueError('registered_resources_require_review')
        return raw

    def prepare(self, provenance):
        if provenance not in ('managed_install','managed_update'): raise ValueError('invalid_provenance')
        state = inspect(self.root,self.catalog,self.path)
        if not all(item['status']=='matches_release' for item in state['resources'].values()):
            raise ValueError('target_resources_do_not_match_registry_release')
        return json.dumps({'schema_version':1,'component':COMPONENT,'version':self.release['version'],
                           'source_revision':self.release['source_revision'],'provenance':provenance,
                           'registered_at':dt.datetime.now(dt.timezone.utc).isoformat(),
                           'resources':{name:{k:v for k,v in item.items() if k!='status'}
                                        for name,item in state['resources'].items()}},indent=2).encode()+b'\n'

    def replace(self, expected, new):
        # Validate the current raw bytes and metadata, but do not reinterpret the
        # old receipt against files already changed by the enclosing transaction.
        if self.current()!=expected: raise ValueError('receipt_changed_externally')
        for directory in (self.path.parent.parent,self.path.parent):
            if directory.is_symlink(): raise ValueError('registry_symlink_requires_review')
            directory.mkdir(mode=0o700,exist_ok=True)
            info=directory.stat()
            if info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o700:
                raise ValueError('unsafe_registry_directory')
        if new is None:
            if expected is not None: self.path.unlink()
        else:
            fd,temporary=tempfile.mkstemp(prefix='.lifecycle-',dir=self.path.parent)
            try:
                with os.fdopen(fd,'wb') as stream:
                    os.fchown(stream.fileno(),0,0);os.fchmod(stream.fileno(),0o600)
                    stream.write(new);stream.flush();os.fsync(stream.fileno())
                if expected is None:
                    os.link(temporary,self.path,follow_symlinks=False)
                else:
                    os.replace(temporary,self.path)
            finally:
                Path(temporary).unlink(missing_ok=True)
        fd=os.open(self.path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)

    def restore(self, before, attempted):
        current=self.current()
        if current==before: return
        if attempted is None or current!=attempted: raise ValueError('receipt_changed_externally')
        self.replace(attempted,before)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=['inspect','adopt'])
    parser.add_argument('--confirm')
    args = parser.parse_args()
    try:
        if args.action=='adopt':
            if args.confirm!=CONFIRM: raise ValueError('explicit --confirm '+CONFIRM+' required')
            result = adopt()
        else:
            result = inspect()
        print(json.dumps(result,ensure_ascii=False,indent=2))
    except (OSError,ValueError,TypeError,KeyError) as error:
        parser.exit(1,'Registry refused: '+str(error)+'\n')


if __name__=='__main__': main()
