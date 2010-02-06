#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Set/get passwords for MSMTP or MPOP in Gnome Keyring

Copyright (C) 2009 Gaizka Villate
              2010 Emmanuel Bouthenot

Original author: Gaizka Villate <gaizkav@gmail.com>
Other author(s): Emmanuel Bouthenot <kolter@openics.org>

URL: http://github.com/gaizka/misc-scripts/tree/master/msmtp

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2 of the License, or (at your
option) any later version.  See http://www.gnu.org/copyleft/gpl.html for
the full text of the license.
"""

import sys, os.path, optparse, getpass

try:
    import gnomekeyring as gk
except ImportError:
    print """Unable to import gnome keyring module
On Debian like systems you probably need to install the following package(s):
python-gnomekeyring"""
    sys.exit(-1)

class keyringManager():

    def __init__(self):
        if os.path.basename(sys.argv[0]).find('msmtp') >= 0:
            self.app = 'msmtp'
            self.protocol = 'smtp'
        elif os.path.basename(sys.argv[0]).find('mpop') >= 0:
            self.app = 'mpop'
            self.protocol = 'pop3'
        else:
            print "ERR: program must contain 'msmtp' or 'mpop' in its name"
            sys.exit(-1)
        # get default keyring name
        try:
            self.keyring = gk.get_default_keyring_sync()
        except gk.NoKeyringDaemonError:
            print "ERR: can't open gnome keyring"
            print "Are you running this program under a GNOME session ?"
            sys.exit(-1)

    def get_app(self):
        return self.app

    def get_protocol(self):
        return self.protocol

    def set(self, user, password, server):
        # display name for password.
        display_name = '%s password for %s at %s' % (self.get_app().upper(), user, server)

        # select type. if you want some kind of "network" password, it seems that
        # appropriate type is network_password because it has a schema already.
        type = gk.ITEM_NETWORK_PASSWORD

        usr_attrs = {'user':user, 'server':server, 'protocol':self.get_protocol()}

        # Now it gets ready to add into the keyring. Do it.
        # Its id will be returned if success or an exception will be raised
        id = gk.item_create_sync(self.keyring, type, display_name, usr_attrs, password, False)
        return id is not None

    def get(self, user, server):
        protocol = self.get_protocol()
        try:
            results = gk.find_network_password_sync(user=user, server=server, protocol=protocol)
        except gk.NoMatchError:
            return None

        return results[0]["password"]

    def getpass(self, username, server):
        ret = True
        passwd = self.get(username, server)
        if passwd is None:
            print "No password set for user '%s' in server '%s'" % (username, server)
            ret = False
        else:
            print "Password for user '%s' in server '%s': '%s'" % (username, server, passwd)

        return ret

    def setpass(self, username, server):
        ret = True
        # Does it already exist?
        if self.get(username, server) is not None:
            print "ERR: %s password for user '%s' in server '%s' already exists, try do delete it first" \
                    % (self.get_app().upper(), username, server)
            ret = False
        else:
            msg = "Password for user '%s' in server '%s' ? " %(username, server)
            passwd = getpass.getpass(msg)
            passwd_confirmation = getpass.getpass("Confirmation ? ")
            if passwd != passwd_confirmation:
                print "ERR: password and password confirmation mismatch"
                ret = False
            else:
                if self.set(username, passwd, server):
                    print "Password successfully set"
                else:
                    print "ERR: Password failed to set"
                    ret = False

        return ret

    def delpass(self, username, server):
        ret = True
        # Does it already exist?
        protocol = self.get_protocol()
        try:
            results = gk.find_network_password_sync(user=username, server=server, protocol=protocol)
        except gk.NoMatchError:
            print "No password set for user '%s' in server '%s'" % (username, server)
            ret = False

        if ret:
            gk.item_delete_sync(self.keyring, results[0]['item_id'])
            print "Password successfully removed"

        return ret

def main():
    ret = True
    km = keyringManager()

    parser = optparse.OptionParser(usage="%prog [-s|-g|-d] --username myuser --server myserver")
    parser.add_option("-s", "--set-password", action="store_true", \
            dest="setpass", help="Set password for %s account" % (km.get_app()))
    parser.add_option("-g", "--get-password", action="store_true", \
            dest="getpass", help="Get password for %s account" % (km.get_app()))
    parser.add_option("-d", "--del-password", action="store_true", \
            dest="delpass", help="Delete password for %s account" % (km.get_app()))
    parser.add_option("-u", "--username", action="store", dest="username", \
            help="Username for %s account" % (km.get_app()))
    parser.add_option("-e", "--server", action="store", dest="server", \
            help="SMTP server for %s account" % (km.get_app()))

    (opts, args) = parser.parse_args()

    if not opts.setpass and not opts.getpass and not opts.delpass:
        parser.print_help()
        print "ERR: You have to use -s or -g or -d"
        ret = False
    elif not opts.username or not opts.server:
        parser.print_help()
        print "ERR: You have to use both --username and --server"
        ret = False
    elif opts.getpass:
        ret = km.getpass(opts.username, opts.server)
    elif opts.setpass:
        ret = km.setpass(opts.username, opts.server)
    elif opts.delpass:
        ret = km.delpass(opts.username, opts.server)
    else:
        print "ERR: Unknown option(s)"
        ret = False

    return ret

if __name__ == '__main__':
    if main():
        sys.exit(0)
    else:
        sys.exit(-1)

