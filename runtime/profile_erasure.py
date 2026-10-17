"""Descriptor-anchored erasure of one immutable, non-default profile home."""
import os
from pathlib import Path
import stat
import uuid


FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def identity(info):
    return info.st_dev, info.st_ino


def open_chain(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('unsafe_data_root')
    descriptors = [os.open('/', FLAGS)]
    links = []
    try:
        for component in path.parts[1:]:
            parent = descriptors[-1]
            child = os.open(component, FLAGS, dir_fd=parent)
            descriptors.append(child)
            links.append((parent, component, child))
        return descriptors, links
    except BaseException:
        for fd in reversed(descriptors):
            os.close(fd)
        raise


def verify(links):
    for parent, name, child in links:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or identity(current) != identity(os.fstat(child)):
            raise ValueError('profile_path_changed')


def empty_directory(fd, links, device):
    for name in os.listdir(fd):
        verify(links)
        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if stat.S_ISDIR(info.st_mode):
            child = os.open(name, FLAGS, dir_fd=fd)
            try:
                opened = os.fstat(child)
                if identity(info) != identity(opened) or opened.st_dev != device:
                    raise ValueError('profile_path_changed')
                child_links = [*links, (fd, name, child)]
                empty_directory(child, child_links, device)
                verify(child_links)
                os.rmdir(name, dir_fd=fd)
            finally:
                os.close(child)
        else:
            # Symlinks are entries, never paths to follow. unlink cannot recurse
            # if a directory replaces an entry between this check and mutation.
            verify(links)
            os.unlink(name, dir_fd=fd)
    os.fsync(fd)


def erase(data_root, profile):
    parsed = uuid.UUID(profile)
    if parsed.version != 4 or str(parsed) != profile:
        raise ValueError('invalid_profile_id')
    descriptors, links = open_chain(data_root)
    try:
        data = descriptors[-1]
        try:
            profiles = os.open('profiles', FLAGS, dir_fd=data)
        except FileNotFoundError:
            verify(links)
            os.fsync(data)
            return
        descriptors.append(profiles)
        links.append((data, 'profiles', profiles))
        try:
            target = os.open(profile, FLAGS, dir_fd=profiles)
        except FileNotFoundError:
            verify(links)
            # A previous rmdir may have succeeded before its directory fsync
            # failed. Absence alone cannot authorize clearing the durable job.
            os.fsync(profiles)
            return
        descriptors.append(target)
        links.append((profiles, profile, target))
        info = os.fstat(target)
        if info.st_uid != os.getuid() or info.st_dev != os.fstat(profiles).st_dev:
            raise ValueError('unsafe_profile_directory')
        empty_directory(target, links, info.st_dev)
        verify(links)
        os.rmdir(profile, dir_fd=profiles)
        os.fsync(profiles)
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
