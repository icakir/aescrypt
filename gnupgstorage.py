# -*- coding: utf-8 -*-
#
#  gnupgstorage.py
#
#  Copyright 2014 Christopher Arndt <chris@chrisarndt.de>
"""File storage with transparent GnuPG en-/decryption.

XXX: does not work yet due to issues with GnuPG!

"""

from __future__ import absolute_import, print_function, unicode_literals

__all__ = ('GnuPGStorage',)

# standard library modules
import logging
import os

from datetime import date, datetime
from os.path import exists, isdir, join

#~try:
#~    from cStringIO import StringIO
#~except ImportError:
#~    from io import StringIO
#~    unicode = str

# third-party modules
import gnupg


log = logging.getLogger(__file__)


# functions


# classes

class GnuPGStorage(object):
    """File storage with transparent GnuPG en-/decryption."""

    def __init__(self, directory, user, passphrase=None, verbose=False):
        """Initialize instance.

        @param dir: storage drectory
        """
        self.storage_dir = directory
        self.user = user
        self.passphrase = passphrase
        self._init_storage()
        self._gpg_dir = join(self.storage_dir, '.gnupg')
        self._gpg = gnupg.GPG(homedir=self._gpg_dir, keyring='pubring.gpg',
            secring='secring.gpg', verbose=verbose)
        self._init_keys()

    def _init_storage(self):
        """Set up the storage directory it doesn't exist."""
        if not exists(self.storage_dir):
            os.mkdir(self.storage_dir)
        elif not isdir(self.storage_dir):
            raise IOError(
                "Storage path '%s' is not a directory." % self.storage_dir)

    def _init_keys(self, expires=None):
        """Create secret/public key pair if it doesn't exist.

        XXX: does not work for unknown reasons. GnuPG refuses to generate a
            valid key :( Which makes the whole module pointless!

        """
        if not self._gpg.list_keys(True):
            key_input = self._key_input(expires)
            self.key = self._gpg.gen_key(key_input)
            log.debug(self.key.fingerprint)

    def _key_input(self, expires=None):
        """Return dict of arguments for key generation."""
        import socket

        key_data = dict(
            name_real=self.user,
            name_email="%s@%s" % (self.user, socket.getfqdn()),
            passphrase=self.passphrase,
            #key_usage='encrypt'
        )

        if expires:
            if isinstance(expires, (date, datetime)):
                key_data['expire_date'] = expires.strftime('%Y-%m-%d')
            else:
                key_data['expire_date'] = expires

        key_input = self._gpg.gen_key_input(save_batchfile=True, **key_data)
        key_input = key_input.splitlines()
        key_input.insert(-1,
            '%%pubring %s' % join(self._gpg_dir, 'pubring.pgp'))
        key_input.insert(-1,
            '%%secring %s' % join(self._gpg_dir, 'secring.pgp'))
        #key_input.insert(-1, '%no-protection')
        log.debug("!!!!!! Key-input: %r", key_input)

        return "\n".join(key_input).encode('utf-8')


    def save(self, name, data):
        """Encrypt and save given data to file with given name."""
        filename = join(self.storage_dir, name)
        if isinstance(data, unicode):
            data = data.encode('utf-8')

        self._gpg.encrypt(data, self.user,
            default_key=self.user,
            armor=False,
            symmetric=False,
            output=filename)
