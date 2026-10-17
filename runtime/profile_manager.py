"""One gateway, independently owned per-profile desktop supervisor processes.

Only the gateway inherits the manager capability. Public viewer authorization is
checked by the gateway before any request reaches this private control service.
No request can choose a command, filesystem path, display slot or descriptor.
"""
import fcntl
import hmac
import json
import importlib.util
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid


def module(name):
    spec = importlib.util.spec_from_file_location(f'auth_browser_{name}', Path(__file__).with_name(f'{name}.py'))
    value = sys.modules.get(spec.name)
    if value is None:
        value = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = value
        spec.loader.exec_module(value)
    return value


context = module('profile_context')
wire = module('profile_wire')
resources = module('profile_resources')
erasure = module('profile_erasure')
CONTROL_PATH = Path('/data/run/profiles-control.sock')
MAX_HISTORY = 4096
WORKER_REPLY_TIMEOUT = 45
WORKER_EXIT_TIMEOUT = 12
CONTROL_IO_TIMEOUT = 2
CLEANUP_TIMEOUT = 20


class ManagerError(RuntimeError):
    cleanup_receipt = None


class Worker:
    def __init__(self, paths, token, *, no_sandbox=False):
        self.paths = paths
        self.process = None
        self.start_token = token
        self.epoch = secrets.token_hex(16)
        self.generation = secrets.token_hex(32)
        self.manifest = None
        self.channel, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self.channel.settimeout(WORKER_REPLY_TIMEOUT)
        environment = paths.environment(os.environ)
        environment['AUTH_BROWSER_PROFILE_WORKER_FD'] = str(child.fileno())
        environment.update({resources.EPOCH_KEY: self.epoch,
                            resources.GENERATION_KEY: self.generation,
                            resources.ROLE_KEY: 'worker'})
        command = [sys.executable, str(Path(__file__).with_name('supervisor.py')), '--profile-worker']
        if no_sandbox:
            command.append('--no-sandbox')
        try:
            paths.prepare()
            self.manifest = resources.create(paths, self.epoch, self.generation)
            self.process = subprocess.Popen(command, env=environment,
                                            pass_fds=(child.fileno(),), start_new_session=True)
        except BaseException:
            self.channel.close()
            raise
        finally:
            child.close()

    def receive(self):
        if self.start_token is not None:
            # The manager publishes this process before sending its start
            # capability. Even an uncertain first write leaves an owned child
            # for explicit stop/shutdown; startup is never sent twice.
            token, self.start_token = self.start_token, None
            try:
                wire.send(self.channel, {'action': 'start', 'token': token})
            except (OSError, ValueError):
                self.channel.close()
                raise
        value, rights = wire.receive(self.channel, allow_rights=True)
        try:
            if value.get('ok') is not True:
                raise ManagerError('profile_start_failed')
            epoch = value.get('fido_gateway_epoch')
            if len(rights) != (1 if epoch is not None else 0):
                raise ManagerError('invalid_worker_reply')
            if epoch is not None:
                if not isinstance(epoch, str) or re.fullmatch(r'[0-9a-f]{32}', epoch) is None:
                    raise ManagerError('invalid_worker_reply')
                # Validation owns only this newly received descriptor. Do not
                # change any other endpoint or infer readiness from its presence.
                endpoint = socket.socket(fileno=rights[0])
                try:
                    if endpoint.family != socket.AF_UNIX or endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET:
                        raise ManagerError('invalid_worker_reply')
                    endpoint.getpeername()
                finally:
                    endpoint.detach()
            owned, rights = rights, []
            return value, owned
        finally:
            wire.close_rights(rights)

    def exchange(self, message):
        wire.send(self.channel, message)
        return self.receive()

    def stopped(self, timeout=0):
        try:
            self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return False
        self.channel.close()
        return self.process.returncode in (0, context.CLEAN_FAILURE_EXIT)


class Record:
    def __init__(self, paths, revision, token):
        self.paths = paths
        self.revision = revision
        self.token = token
        self.bound_token = None
        self.epoch = None
        self.worker = None
        self.state = 'starting'
        self.manifest = None
        self.display_lease = None
        self.cleanup_attempted = False
        self.cleanup_error = None
        self.operation = threading.Lock()


class ProfileManager:
    def __init__(self, *, no_sandbox=False, worker_factory=Worker, roots=None):
        self.no_sandbox = no_sandbox
        self.worker_factory = worker_factory
        self.roots = roots or {}
        self.token = secrets.token_hex(32)
        self.records = {}
        self.lock = threading.Lock()
        self.slots = {}
        self.revisions = {}
        # The gateway uses one increasing sequence for all lifecycle requests.
        # Retiring a deleted identity advances this scalar instead of retaining
        # its revision forever; delayed requests cannot recreate its resources.
        self.retired_revision = 0
        # Retain only the last confirmed, reaped epoch per profile. This shares
        # the bounded revision-history lifetime and never stands in for a live
        # record or an uncertain cleanup.
        self.stopped_epochs = {}
        # Keep successful erasure proof only until the gateway acknowledges its
        # durable journal commit. A lost reply must not strand a deletion when
        # harmless, unowned files remain in the stopped runtime directory.
        self.deleted_profiles = set()
        self.inflight = threading.BoundedSemaphore(context.MAX_PROFILES)
        self.stopping = False
        self.listener = None
        self.gateway = None
        self.gateway_retry = None
        self.gateway_backoff = 1
        self.manager_lock = None
        self.startup_blocked = False
        self.startup_cleanup_done = False
        self.startup_pristine = False
        self.startup_unaccounted = False
        self.cleanup_operation = threading.Lock()

    def validate(self, request):
        if not isinstance(request, dict) or set(request) - {
                'version', 'token', 'request_id', 'action', 'profile_id', 'revision', 'runtime_epoch', 'cleanup_profiles', 'cleanup_stop_profiles', 'attach_gateway'}:
            raise ManagerError('invalid_request')
        if type(request.get('version')) is not int or request['version'] != 1 or request.get('action') not in ('ensure', 'stop', 'delete_data', 'forget_deleted', 'health', 'cleanup', 'cleanup_status', 'cleanup_startup'):
            raise ManagerError('invalid_request')
        if 'attach_gateway' in request and (request['action'] != 'ensure'
                or type(request['attach_gateway']) is not bool):
            raise ManagerError('invalid_request')
        token = request.get('token')
        if not isinstance(token, str) or re.fullmatch(r'[0-9a-f]{64}', token) is None or not hmac.compare_digest(token, self.token):
            raise ManagerError('unauthorized')
        try:
            if str(uuid.UUID(request['request_id'])) != request['request_id']:
                raise ValueError()
        except (KeyError, TypeError, ValueError, AttributeError):
            raise ManagerError('invalid_request') from None
        if not context.valid_profile_id(request.get('profile_id')):
            raise ManagerError('invalid_request')
        revision = request.get('revision')
        if type(revision) is not int or not 0 < revision < 1 << 64:
            raise ManagerError('invalid_request')
        epoch = request.get('runtime_epoch')
        if epoch is not None and (request['action'] != 'stop' or not isinstance(epoch, str)
                                  or re.fullmatch(r'[0-9a-f]{32}', epoch) is None):
            raise ManagerError('invalid_request')
        candidates = request.get('cleanup_profiles')
        if candidates is not None and (request['action'] not in ('cleanup', 'cleanup_status', 'cleanup_startup')
                or not isinstance(candidates, list) or len(candidates) > context.MAX_PROFILES
                or any(not context.valid_profile_id(profile) for profile in candidates)
                or len(set(candidates)) != len(candidates)):
            raise ManagerError('invalid_request')
        stops = request.get('cleanup_stop_profiles')
        if stops is not None:
            if request['action'] not in ('cleanup', 'cleanup_startup') or not isinstance(stops, list) or len(stops) > context.MAX_PROFILES:
                raise ManagerError('invalid_request')
            seen = set()
            for item in stops:
                if (not isinstance(item, dict) or set(item) != {'profile_id', 'runtime_epoch'}
                        or not context.valid_profile_id(item['profile_id'])
                        or item['profile_id'] not in (candidates or []) or item['profile_id'] in seen
                        or (item['runtime_epoch'] is not None and (not isinstance(item['runtime_epoch'], str)
                            or re.fullmatch(r'[0-9a-f]{32}', item['runtime_epoch']) is None))):
                    raise ManagerError('invalid_request')
                seen.add(item['profile_id'])
        if request['action'] in ('cleanup', 'cleanup_status', 'cleanup_startup') and request['profile_id'] != 'default':
            raise ManagerError('invalid_request')

    def current(self, request, record):
        return (not self.stopping and request['token'] == self.token
                and self.records.get(request['profile_id']) is record
                and record.token == self.token and record.revision == request['revision'])

    def handle(self, request):
        self.validate(request)
        if request['action'] in ('cleanup', 'cleanup_status', 'cleanup_startup'):
            return self.cleanup(request, reconcile=request['action'] != 'cleanup_status'), []
        if request['action'] == 'delete_data':
            return self.delete_data(request), []
        if request['action'] == 'forget_deleted':
            return self.forget_deleted(request), []
        rights = []
        with self.lock:
            self.validate(request)
            if self.stopping:
                raise ManagerError('runtime_unavailable')
            if request['action'] == 'health':
                # Health has no lifecycle side effects, including revision
                # advancement or creation of the otherwise lazy default stack.
                alive = not self.startup_blocked and not self.startup_unaccounted and all(
                    record.state == 'running' and record.worker is not None
                    and record.worker.process.poll() is None for record in self.records.values())
                return self.response(request, manager_ready=True, profiles_alive=alive), []
            existing = self.records.get(request['profile_id'])
            known_live = (existing is not None and existing.state == 'running'
                          and existing.worker is not None and existing.worker.process.poll() is None)
            if self.startup_blocked or (self.startup_unaccounted and request['action'] == 'ensure' and not known_live):
                raise ManagerError('cleanup_unconfirmed')
            profile = request['profile_id']
            revision = request['revision']
            if request['action'] == 'ensure' and profile in self.deleted_profiles:
                raise ManagerError('stale_revision')
            if profile not in self.revisions and revision <= self.retired_revision:
                raise ManagerError('stale_revision')
            previous = self.revisions.get(profile, 0)
            record = self.records.get(profile)
            if revision < previous or (revision == previous and (
                    (request['action'] == 'ensure' and record is None)
                    or (request['action'] == 'stop' and record is not None))):
                raise ManagerError('stale_revision')
            if profile not in self.revisions and len(self.revisions) >= MAX_HISTORY:
                raise ManagerError('revision_capacity')
            if request.get('runtime_epoch') is not None:
                expected_epoch = record.epoch if record is not None else self.stopped_epochs.get(profile)
                if expected_epoch != request['runtime_epoch']:
                    raise ManagerError('stale_runtime')
            self.revisions[profile] = revision
            if record is None and request['action'] == 'ensure':
                slot = next((slot for slot in range(context.MAX_PROFILES) if slot not in self.slots), None)
                if slot is None:
                    raise ManagerError('runtime_capacity')
                paths = context.ProfilePaths(profile, slot, **self.roots)
                record = Record(paths, revision, self.token)
                self.records[profile] = record
                self.stopped_epochs.pop(profile, None)
                self.slots[slot] = profile
            elif record is not None:
                record.revision = revision
                record.token = self.token
            if record is None:
                return self.response(request, stopped=True), []
        # Per-profile serialization never holds the global registry lock during
        # process startup/shutdown. A newer stop advances the revision first,
        # making an in-flight old ensure unable to publish its capability.
        with record.operation:
            with self.lock:
                if not self.current(request, record):
                    raise ManagerError('stale_revision')
            try:
                if request['action'] == 'stop':
                    # Explicit teardown can retry a previous failed cleanup;
                    # only automatic recovery is limited to one attempt.
                    record.state = 'cleanup_unconfirmed'
                    record.cleanup_attempted = True
                    if not self.reconcile_record(record, time.monotonic() + CLEANUP_TIMEOUT,
                                                 expected_request=request):
                        raise ManagerError('cleanup_unconfirmed')
                    return self.response(request, stopped=True), []
                if record.state == 'cleanup_unconfirmed':
                    raise ManagerError('cleanup_unconfirmed')
                if record.worker is None:
                    with self.lock:
                        if not self.current(request, record):
                            raise ManagerError('stale_revision')
                        # Publish process ownership before shutdown can snapshot
                        # children. This constructor starts but never awaits readiness.
                        record.worker = self.worker_factory(record.paths, request['token'], no_sandbox=self.no_sandbox)
                        record.epoch = getattr(record.worker, 'epoch', None)
                        record.manifest = getattr(record.worker, 'manifest', None)
                    reply, rights = record.worker.receive()
                    epoch = reply.get('runtime_epoch')
                    if not isinstance(epoch, str) or re.fullmatch(r'[0-9a-f]{32}', epoch) is None:
                        raise ManagerError('invalid_worker_reply')
                    if record.epoch is not None and epoch != record.epoch:
                        raise ManagerError('invalid_worker_reply')
                    record.epoch = epoch
                    record.bound_token = request['token']
                    record.state = 'running'
                elif record.state == 'cleanup_unconfirmed':
                    raise ManagerError('cleanup_unconfirmed')
                elif record.state != 'running':
                    # A failed/uncertain start cannot be promoted by a second
                    # ensure. Its process and slot stay owned until stop.
                    raise ManagerError('profile_start_failed')
                elif record.worker.process.poll() is not None:
                    raise ManagerError('profile_exited')
                elif record.bound_token != request['token'] or request.get('attach_gateway', False):
                    # A fresh gateway context may have lost an initial offer
                    # after admission. Explicit attachment renews only its FIDO
                    # leg; ordinary cached ensures must preserve a live leg.
                    reply, rights = record.worker.exchange({'action': 'gateway', 'token': request['token']})
                    if reply.get('runtime_epoch') != record.epoch:
                        raise ManagerError('invalid_worker_reply')
                    record.bound_token = request['token']
                else:
                    reply = {}
                with self.lock:
                    if not self.current(request, record):
                        raise ManagerError('stale_revision')
                    result = self.response(request, runtime_epoch=record.epoch, engine_ready=False,
                                           **record.paths.metadata())
                    if 'fido_gateway_epoch' in reply:
                        result['fido_gateway_epoch'] = reply['fido_gateway_epoch']
                owned, rights = rights, []
                return result, owned
            except (OSError, ValueError, ManagerError) as error:
                if request['action'] == 'ensure' and str(error) != 'stale_revision':
                    with self.lock:
                        eligible = self.records.get(profile) is record and record.state != 'running'
                    if record.worker is not None and record.worker.process.poll() is not None:
                        eligible = True
                    if eligible:
                        record.state = 'cleanup_unconfirmed'
                        confirmed = self.automatic_cleanup(record)
                        failure = error if isinstance(error, ManagerError) else ManagerError('profile_start_failed')
                        if confirmed:
                            failure.cleanup_receipt = dict(cleanup_confirmed=True, runtime_epoch=record.epoch,
                                                           revision=request['revision'])
                        raise failure from None
                raise
            finally:
                wire.close_rights(rights)

    def delete_data(self, request):
        # Hold admission throughout proof and erasure: no ensure can publish a
        # new worker between checking the registry and deleting its home.
        with self.lock:
            self.validate(request)
            profile = request['profile_id']
            revision = request['revision']
            if profile == 'default':
                raise ManagerError('invalid_request')
            if self.stopping:
                raise ManagerError('runtime_unavailable')
            if (not self.startup_cleanup_done or self.startup_blocked
                    or self.startup_unaccounted or profile in self.records):
                raise ManagerError('cleanup_unconfirmed')
            if ((profile not in self.revisions and revision <= self.retired_revision)
                    or revision < self.revisions.get(profile, 0)):
                raise ManagerError('stale_revision')
            if profile not in self.revisions and len(self.revisions) >= MAX_HISTORY:
                raise ManagerError('revision_capacity')
            if profile not in self.deleted_profiles and len(self.deleted_profiles) >= MAX_HISTORY:
                raise ManagerError('revision_capacity')
            if not self.absent_profile_proven(profile):
                raise ManagerError('cleanup_unconfirmed')
            self.revisions[profile] = revision
            try:
                erasure.erase(self.roots.get('data', context.DATA_ROOT), profile)
            except PermissionError:
                raise ManagerError('profile_data_permission_denied') from None
            except ValueError:
                raise ManagerError('profile_data_unsafe_path') from None
            except OSError:
                raise ManagerError('profile_data_delete_failed') from None
            self.deleted_profiles.add(profile)
            return self.response(request, browser_data_deleted=True)

    def forget_deleted(self, request):
        # This acknowledgement follows the gateway's durable journal commit.
        # It never erases files, stops processes or forgets an unconfirmed job.
        with self.lock:
            self.validate(request)
            profile = request['profile_id']
            if profile == 'default':
                raise ManagerError('invalid_request')
            if self.stopping:
                raise ManagerError('runtime_unavailable')
            if profile in self.records:
                raise ManagerError('cleanup_unconfirmed')
            if profile in self.deleted_profiles:
                if request['revision'] < self.revisions.get(profile, 0):
                    raise ManagerError('stale_revision')
                self.retired_revision = max(self.retired_revision, request['revision'])
                self.deleted_profiles.remove(profile)
                self.revisions.pop(profile, None)
                self.stopped_epochs.pop(profile, None)
            return self.response(request, forgotten=True)

    def absent_profile_proven(self, profile):
        # Call with the registry lock. Revision history is ordering information,
        # not resource ownership: a no-op stop advances it without ever starting
        # a worker. Such a stop must not invalidate a pristine namespace proof.
        if profile in self.records or self.startup_blocked or self.startup_unaccounted:
            return False
        if profile in self.stopped_epochs or profile in self.deleted_profiles:
            return True
        if not self.startup_pristine:
            return False
        path = Path(self.roots.get('run', context.RUN_ROOT)) / profile
        if not path.exists() and not path.is_symlink():
            return True
        if not path.is_symlink():
            try:
                context.private_directory(path)
                return not any(path.iterdir())
            except (OSError, ValueError):
                pass
        return False

    def stop_worker(self, record, deadline=None):
        worker = record.worker
        if worker is None:
            return record.manifest is None and record.display_lease is None
        remaining = lambda: (WORKER_EXIT_TIMEOUT if deadline is None else
                             max(0, min(WORKER_EXIT_TIMEOUT, deadline - time.monotonic())))
        if worker.process.poll() is None:
            if deadline is not None and remaining() <= 0:
                return False
            old_timeout = worker.channel.gettimeout() if hasattr(worker, 'channel') else None
            try:
                if hasattr(worker, 'channel') and deadline is not None:
                    worker.channel.settimeout(max(.001, deadline - time.monotonic()))
                reply, received = worker.exchange({'action': 'stop'})
                wire.close_rights(received)
                if reply.get('stopped') is not True:
                    return False
            except (OSError, ValueError, ManagerError):
                pass
            finally:
                if hasattr(worker, 'channel') and worker.channel.fileno() >= 0:
                    worker.channel.settimeout(old_timeout)
        if not worker.stopped(timeout=remaining()):
            return False
        if record.manifest is not None:
            try:
                if resources.scan(record.manifest, deadline=deadline):
                    return False
                resources.remove_transient(record.paths, record.manifest)
                record.manifest = None
            except (OSError, ValueError, resources.ResourceError):
                return False
        return True

    def complete_record(self, record):
        # Call with the registry lock after actual process/resource reconciliation.
        profile = record.paths.profile_id
        if self.records.get(profile) is not record:
            return False
        if record.epoch is not None:
            self.stopped_epochs[profile] = record.epoch
        self.records.pop(profile)
        self.slots.pop(record.paths.slot, None)
        return True

    def reconcile_record(self, record, deadline, *, expected_request=None):
        # The per-profile operation lock is held throughout. A new generation
        # cannot be allocated until completion removes this exact old record.
        record.cleanup_error = None
        try:
            if record.manifest is not None:
                try:
                    persisted = resources.read(record.paths)
                except FileNotFoundError:
                    # Missing ownership files cannot authorize new signals.
                    # They are harmless only after the saved generation is gone.
                    if resources.scan(record.manifest, deadline=deadline):
                        raise resources.ResourceError('ownership_unconfirmed') from None
                else:
                    if persisted != record.manifest:
                        raise resources.ResourceError('resource_generation_changed')
                    if record.worker is not None and record.worker.process.poll() is None:
                        # Reserve the cleanup budget for verified forced teardown
                        # if private graceful close is stuck or its reply is lost.
                        graceful_deadline = min(deadline, time.monotonic() + 1)
                        if self.stop_worker(record, graceful_deadline):
                            with self.lock:
                                if expected_request is not None and not self.current(expected_request, record):
                                    raise ManagerError('stale_revision')
                                return self.complete_record(record)
                    # Graceful stop may have awaited other work: revalidate the
                    # durable generation immediately before forced signaling.
                    if resources.read(record.paths) != record.manifest:
                        raise resources.ResourceError('resource_generation_changed')
                    if resources.retired_namespace(record.manifest):
                        # A previous container's numeric PIDs are never signal
                        # authority. Only inactive, exactly recorded transients
                        # may be removed under our exclusive manager lock.
                        if record.worker is not None or self.manager_lock is None:
                            raise resources.ResourceError('ownership_unconfirmed')
                        resources.confirm_retired_transient(record.paths, record.manifest, deadline)
                    elif not resources.reconcile(record.manifest, deadline, force=True):
                        raise resources.ResourceError('process_survived')
                if record.worker is not None:
                    # A forced negative exit code is expected; complete only
                    # after both generation absence and actual child reaping.
                    record.worker.process.wait(timeout=max(0, deadline - time.monotonic()))
                    record.worker.channel.close()
                resources.remove_transient(record.paths, record.manifest)
                record.manifest = None
            elif record.display_lease is not None:
                lease = resources.read_display(record.paths.profile_id)
                if lease != record.display_lease:
                    raise resources.ResourceError('display_generation_changed')
                if all(lease[key] == value for key, value in resources.namespace().items()):
                    if not resources.reconcile(lease, deadline, force=True):
                        raise resources.ResourceError('process_survived')
                resources.remove_display(record.paths, lease)
                resources.remove_display_lease(record.paths, lease)
                record.display_lease = None
            elif record.worker is not None:
                # Private graceful stop needs no filesystem signal authority;
                # without a manifest, forced process cleanup stays forbidden.
                if not self.stop_worker(record, min(deadline, time.monotonic() + 1)):
                    raise resources.ResourceError('ownership_unconfirmed')
        except PermissionError:
            record.cleanup_error = 'permission_denied'
            return False
        except subprocess.TimeoutExpired:
            record.cleanup_error = 'process_survived'
            return False
        except resources.ResourceError as error:
            record.cleanup_error = str(error).split(':', 1)[0]
            return False
        except (OSError, ValueError):
            record.cleanup_error = 'ownership_unconfirmed'
            return False
        with self.lock:
            if expected_request is not None and not self.current(expected_request, record):
                raise ManagerError('stale_revision')
            return self.complete_record(record)

    def automatic_cleanup(self, record):
        if record.cleanup_attempted:
            return False
        record.cleanup_attempted = True
        try:
            # A constructor can fail after writing the ownership manifest but
            # before it returns a Worker. Recover that evidence before deciding.
            if record.manifest is None and record.worker is None:
                try:
                    record.manifest = resources.read(record.paths)
                    record.epoch = record.manifest['runtime_epoch']
                except FileNotFoundError:
                    pass
            return self.reconcile_record(record, time.monotonic() + CLEANUP_TIMEOUT)
        except (OSError, ValueError, resources.ResourceError):
            return False

    def cleanup(self, request=None, *, reconcile=True):
        if not self.cleanup_operation.acquire(blocking=False):
            raise ManagerError('cleanup_busy')
        try:
            with self.lock:
                if request is not None:
                    self.validate(request)
                if self.stopping:
                    raise ManagerError('runtime_unavailable')
                records = list(self.records.values())
                token = self.token
            deadline = time.monotonic() + CLEANUP_TIMEOUT
            candidates = set(request.get('cleanup_profiles', [])) if request else set()
            stops = {item['profile_id']: item['runtime_epoch']
                     for item in request.get('cleanup_stop_profiles', [])} if request else {}
            results = []
            skipped = 0
            for record in records:
                profile = record.paths.profile_id
                with self.lock:
                    if self.records.get(profile) is not record:
                        # A completed snapshot entry is no longer a resource to
                        # skip. Requested profiles still receive current proof
                        # below, without acting on a replacement generation.
                        continue
                candidates.discard(profile)
                was_starting = record.state == 'starting'
                explicit_stop = profile in stops and (stops[profile] is None or stops[profile] == record.epoch)
                # A caller's uncertainty never turns a live healthy generation
                # into cleanup eligibility. Explicit stop remains a separate API.
                if not explicit_stop and record.state == 'running' and record.worker is not None and record.worker.process.poll() is None:
                    if request and profile in request.get('cleanup_profiles', []):
                        results.append(dict(profile_id=profile, runtime_epoch=record.epoch, stopped=False))
                    else:
                        skipped += 1
                    continue
                confirmed = False
                startup_intent = request is not None and request['action'] == 'cleanup_startup'
                eligible = not startup_intent or (explicit_stop and not record.cleanup_attempted)
                acquired = False
                if reconcile and eligible and record.operation.acquire(blocking=False):
                    acquired = True
                    try:
                        with self.lock:
                            current = self.records.get(profile) is record and self.token == token and not self.stopping
                        epoch_matches = profile not in stops or stops[profile] is None or stops[profile] == record.epoch
                        if not current:
                            if request and profile in request.get('cleanup_profiles', []):
                                candidates.add(profile)
                            continue
                        # The snapshot may have caught an ensure before it
                        # published running state. Recheck under its operation
                        # lock so cleanup cannot stop the healthy result.
                        healthy = (record.state == 'running' and record.worker is not None
                                   and record.worker.process.poll() is None)
                        if not explicit_stop and (healthy or record.state == 'starting'):
                            if request and profile in request.get('cleanup_profiles', []):
                                results.append(dict(profile_id=profile, runtime_epoch=record.epoch, stopped=False))
                            else:
                                skipped += 1
                            continue
                        if epoch_matches and time.monotonic() < deadline:
                            if startup_intent:
                                record.cleanup_attempted = True
                            record.state = 'cleanup_unconfirmed'
                            confirmed = self.reconcile_record(record, deadline)
                    finally:
                        record.operation.release()
                if (not acquired and (was_starting or record.state == 'starting') and not explicit_stop
                        and (request is None or profile not in request.get('cleanup_profiles', []))):
                    # A busy unrelated startup is neither failed nor an intent
                    # to stop. Publishing failure here could taint its eventual
                    # successful epoch when the gateway receives this snapshot.
                    skipped += 1
                    continue
                result = dict(profile_id=profile, runtime_epoch=record.epoch, stopped=confirmed)
                if not confirmed and record.cleanup_error is not None:
                    result['error'] = record.cleanup_error
                results.append(result)
            if request is not None and request['action'] == 'cleanup' and self.startup_cleanup_done:
                self.refresh_startup_inventory(deadline)
            with self.lock:
                for profile in sorted(candidates):
                    current = self.records.get(profile)
                    epoch = current.epoch if current is not None else self.stopped_epochs.get(profile)
                    # An exact stopped epoch or a pristine, empty runtime
                    # namespace is required; a revised no-op stop is harmless.
                    results.append(dict(profile_id=profile, runtime_epoch=epoch,
                                        stopped=self.absent_profile_proven(profile)))
                # Resend a lost completion acknowledgement without retaining a
                # live record or adding a skipped item. Requested candidates
                # take priority and the shared reply limit stays unchanged.
                reported = {item['profile_id'] for item in results}
                for profile in sorted(self.deleted_profiles - reported):
                    if len(results) >= 2 * context.MAX_PROFILES:
                        break
                    results.append(dict(profile_id=profile,
                                        runtime_epoch=self.stopped_epochs.get(profile),
                                        stopped=self.absent_profile_proven(profile)))
            fields = dict(cleaned=sum(item['stopped'] for item in results),
                          pending=sum(not item['stopped'] for item in results), skipped=skipped, results=results)
            if self.startup_blocked or (request is not None and self.startup_unaccounted):
                # Unknown prior runtime files cannot be assigned a generation.
                # Keep admission blocked and expose the failure instead of
                # silently reporting successful cleanup of an empty registry.
                raise ManagerError('cleanup_unconfirmed')
            return self.response(request, **fields) if request else fields
        finally:
            self.cleanup_operation.release()

    def refresh_startup_inventory(self, deadline):
        if time.monotonic() >= deadline:
            return
        with self.lock:
            records = list(self.records.values())
            generations = {evidence['generation'] for record in records
                           if (evidence := record.manifest or record.display_lease) is not None}
            slots = {record.paths.slot for record in records}
            gateway = self.gateway
            token = self.token
            inventory = [(record, record.epoch, record.manifest, record.display_lease) for record in records]
        allowed_processes = {}
        if gateway is not None and gateway.poll() is None:
            try:
                info = resources.identity(gateway.pid)
                allowed_processes[gateway.pid] = (info[0], info[2])
            except (OSError, ValueError):
                pass
        root = Path(self.roots.get('run', context.RUN_ROOT))
        accounted = resources.pristine_start(root, context.MAX_PROFILES, deadline=deadline,
                                             allowed_generations=generations, allowed_slots=slots,
                                             allowed_processes=allowed_processes)
        if accounted is None:
            # A known failed generation can consume this pass's budget. An
            # inconclusive inventory does not invalidate an earlier proof.
            return
        with self.lock:
            # Startup/stop can progress while /proc is scanned. Its allowance
            # snapshot then describes neither the old nor the new inventory;
            # discard it rather than poisoning or granting global admission.
            current = [(record, record.epoch, record.manifest, record.display_lease)
                       for record in self.records.values()]
            if current != inventory or self.gateway is not gateway or self.token != token:
                return
            self.startup_unaccounted = not accounted
            if not accounted:
                self.startup_pristine = False
            if accounted and not self.startup_blocked:
                # The inventory proves there are no unowned generations even
                # when other profiles are live. A recovered inventory must also
                # restore absence proofs for profiles that never had a worker.
                self.startup_pristine = True

    def acquire_manager_lock(self, path):
        if self.manager_lock is not None:
            return
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise ManagerError('unsafe_manager_lock')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ManagerError('manager_already_running') from None
            self.manager_lock = fd
        except BaseException:
            os.close(fd)
            raise

    def startup_cleanup(self):
        if self.startup_cleanup_done:
            return
        self.startup_cleanup_done = True
        self.startup_unaccounted = True
        startup_deadline = time.monotonic() + CLEANUP_TIMEOUT
        root = Path(self.roots.get('run', context.RUN_ROOT))
        context.private_directory(root)
        entries = list(root.iterdir())
        if len(entries) > MAX_HISTORY:
            self.startup_blocked = True
            return
        for entry in entries:
            if not context.valid_profile_id(entry.name):
                continue
            try:
                context.private_directory(entry)
                manifest_path = entry / resources.MANIFEST
                if not manifest_path.exists() and not manifest_path.is_symlink():
                    if any((entry / name).exists() or (entry / name).is_symlink()
                           for name in resources.SOCKETS | resources.FILES):
                        self.startup_blocked = True
                    continue
                # Read the bounded slot before constructing its canonical paths;
                # resources.read performs full ownership/schema validation.
                fd = os.open(manifest_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
                with os.fdopen(fd, 'r') as source:
                    info = os.fstat(source.fileno())
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                            or stat.S_IMODE(info.st_mode) != 0o600):
                        raise ValueError('unsafe manifest')
                    raw = source.read(2049)
                if len(raw) > 2048:
                    raise ValueError('manifest size')
                value = json.loads(raw)
                if not isinstance(value, dict):
                    raise ValueError('invalid manifest')
                slot = value.get('slot')
                paths = context.ProfilePaths(entry.name, slot, **self.roots)
                manifest = resources.read(paths)
                if slot in self.slots or len(self.records) >= context.MAX_PROFILES:
                    raise ValueError('ambiguous runtime slots')
                record = Record(paths, 0, self.token)
                record.manifest = manifest
                record.epoch = manifest['runtime_epoch']
                record.state = 'cleanup_unconfirmed'
                record.cleanup_attempted = True
                self.records[entry.name] = record
                self.slots[slot] = entry.name
            except (OSError, ValueError, resources.ResourceError):
                self.startup_blocked = True
        try:
            resources.display_directory(create=True)
            leases = list(resources.DISPLAY_ROOT.iterdir())
            if len(leases) > MAX_HISTORY:
                raise ValueError('display lease capacity')
            for path in leases:
                if path.suffix != '.json' or not context.valid_profile_id(path.stem):
                    self.startup_blocked = True
                    continue
                lease = resources.read_display(path.stem)
                current = self.records.get(path.stem)
                if current is not None:
                    if current.epoch != lease['runtime_epoch'] or current.paths.slot != lease['slot']:
                        self.startup_blocked = True
                    continue
                if lease['slot'] in self.slots or len(self.records) >= context.MAX_PROFILES:
                    self.startup_blocked = True
                    continue
                paths = context.ProfilePaths(path.stem, lease['slot'], **self.roots)
                record = Record(paths, 0, self.token)
                record.epoch = lease['runtime_epoch']
                record.display_lease = lease
                record.state = 'cleanup_unconfirmed'
                record.cleanup_attempted = True
                self.records[path.stem] = record
                self.slots[lease['slot']] = path.stem
        except (OSError, ValueError, resources.ResourceError):
            self.startup_blocked = True
        try:
            result = self.cleanup()
            self.refresh_startup_inventory(startup_deadline)
            if self.startup_unaccounted:
                raise ManagerError('cleanup_unconfirmed')
            print('[supervisor] Startup resource cleanup: '
                  f"cleaned={result['cleaned']} pending={result['pending']} skipped={result['skipped']}", flush=True)
        except ManagerError:
            print('[supervisor] Startup resource cleanup is unconfirmed; unresolved resources remain reserved.',
                  file=sys.stderr, flush=True)

    @staticmethod
    def response(request, **fields):
        return dict(ok=True, version=1, request_id=request['request_id'],
                    profile_id=request['profile_id'], revision=request['revision'], **fields)

    def connection(self, connection):
        rights = []
        request = {}
        sending = False
        try:
            connection.settimeout(CONTROL_IO_TIMEOUT)
            request, unexpected = wire.receive(connection)
            wire.close_rights(unexpected)
            result, rights = self.handle(request)
            connection.settimeout(CONTROL_IO_TIMEOUT)
            sending = True
            wire.send(connection, result, rights[0] if rights else None)
        except (OSError, ValueError, ManagerError) as error:
            # No raw payload, capability, path, URL or child log enters errors.
            # A failed/partial success write is uncertain and is not retried.
            try:
                if sending:
                    return
                code = str(error) if isinstance(error, ManagerError) else 'runtime_unavailable'
                identifier = request.get('request_id')
                profile = request.get('profile_id')
                receipt = getattr(error, 'cleanup_receipt', None) or {}
                wire.send(connection, dict(ok=False, version=1,
                          request_id=identifier if isinstance(identifier, str) and len(identifier) <= 36 else None,
                          profile_id=profile if context.valid_profile_id(profile) else None,
                          error=code, **receipt))
            except (OSError, ValueError):
                pass
        finally:
            wire.close_rights(rights)
            connection.close()
            self.inflight.release()

    def open(self, path=CONTROL_PATH):
        context.private_directory(path.parent)
        self.acquire_manager_lock(path.parent / 'profiles-manager.lock')
        if path.is_symlink() or (path.exists() and not stat.S_ISSOCK(path.lstat().st_mode)):
            raise ManagerError('unsafe_control_path')
        path.unlink(missing_ok=True)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM | socket.SOCK_CLOEXEC)
        self.listener.bind(str(path))
        path.chmod(0o600)
        self.listener.listen(context.MAX_PROFILES)
        self.listener.settimeout(.2)

    def start_gateway(self):
        environment = dict(os.environ)
        for key in tuple(environment):
            if key.startswith('UHF_') or key.startswith('AUTH_BROWSER_PROFILE_') or key in (
                    'LD_PRELOAD', 'AUTH_BROWSER_FIDO_CONTROL_FD', 'AUTH_BROWSER_FIDO_GATEWAY_EPOCH'):
                environment.pop(key)
        environment.update(AUTH_BROWSER_PROFILE_CONTROL_PATH=str(CONTROL_PATH),
                           AUTH_BROWSER_PROFILE_CONTROL_TOKEN=self.token)
        self.gateway = subprocess.Popen(['/usr/local/bin/webauthn-browser'], env=environment,
                                        start_new_session=True)

    def gateway_lost(self):
        with self.lock:
            old = self.token
            self.token = secrets.token_hex(32)
            self.revisions.clear()
            # Successful erasure is independent of gateway authority. Retain
            # only its unacknowledged proof across a gateway crash, so a lost
            # journal commit can still be replayed without touching old files.
            self.stopped_epochs = {profile: epoch for profile, epoch in self.stopped_epochs.items()
                                   if profile in self.deleted_profiles}
            self.retired_revision = 0
            records = list(self.records.values())
        for record in records:
            def retire(record=record):
                with record.operation:
                    if record.bound_token != old or record.worker is None:
                        return
                    try:
                        _, rights = record.worker.exchange({'action': 'gateway_lost'})
                        wire.close_rights(rights)
                    except (OSError, ValueError, ManagerError):
                        pass
                    record.bound_token = None
            threading.Thread(target=retire, daemon=True).start()

    def shutdown(self):
        with self.lock:
            self.stopping = True
            children = [r.worker.process for r in self.records.values() if r.worker is not None]
            workers = [r.worker for r in self.records.values() if r.worker is not None]
        if self.listener:
            self.listener.close()
        # Container shutdown retains the existing TERM-then-bounded-KILL policy.
        # User profile disable uses handle(stop), with no browser hard-kill fallback.
        if self.gateway is not None:
            children.append(self.gateway)
        for child in children:
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        for child in children:
            try:
                child.wait(timeout=12)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()
        for worker in workers:
            worker.channel.close()
        if self.manager_lock is not None:
            os.close(self.manager_lock)
            self.manager_lock = None

    def run(self):
        if os.getuid() == 0:
            raise RuntimeError('Profile manager must run as the application user')
        os.umask(0o077)
        context.prepare_x_socket_dir()
        self.open()
        self.startup_cleanup()
        self.start_gateway()
        while not self.stopping:
            if self.gateway is not None and self.gateway.poll() is not None:
                self.gateway.wait()
                self.gateway = None
                self.gateway_lost()
                self.gateway_retry = time.monotonic() + self.gateway_backoff
                self.gateway_backoff = min(30, self.gateway_backoff * 2)
            if self.gateway is None and self.gateway_retry is not None and time.monotonic() >= self.gateway_retry:
                self.start_gateway()
                self.gateway_retry = None
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            if not self.inflight.acquire(blocking=False):
                connection.close()
                continue
            threading.Thread(target=self.connection, args=(connection,), daemon=True).start()


def main(*, no_sandbox=False):
    manager = ProfileManager(no_sandbox=no_sandbox)
    def stop(_signal, _frame):
        manager.stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        manager.run()
        return 0
    except Exception:
        print('[supervisor] Profile manager failed; inspect service availability.', file=sys.stderr, flush=True)
        return 1
    finally:
        manager.shutdown()
