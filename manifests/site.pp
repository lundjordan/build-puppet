# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

import "stages.pp"
# both of these should be symlnks to the appropriate organization
import "config.pp"
import "nodes.pp"

# Default to 0:0, 0644 on POSIX, and root, 0644 on Windows
case $::operatingsystem {
    Windows: {
        File {
            owner => root,
            backup => false,
            mode => filemode(0644),
        }
    }
    default: {
        File {
            owner => 0,
            group => 0,
            mode => filemode(0644),
            backup => false,
        }
    }
}

Concat {
    backup => false
}

Concat::Fragment {
    backup => false
}

# the default value for allow_virtual will change to true in Puppet-4.0.0, so be explicit
Package {
    allow_virtual => false
}

# purge unknown users from the system's user database.  This doesn't work on Windows
# due to https://projects.puppetlabs.com/issues/22048
# TODO-WIN: figre out how to not purge system users on windows (solve the puppetlabs bug)
if ($::operatingsystem != "windows") {
    resources {
        'user':
            purge => true;
    }
}

# The PuppetLabs firewall module is only supported on Linux
case $operatingsystem {
    CentOS,Ubuntu: {
        # similarly, set up the firewall resource, but note that this does not activate
        # the firewall
        resources {
            'firewall':
                purge => true;
        }

        # put the default rules before/after any custom rules
        Firewall {
            require => Class['fw::pre'],
            before => Class['fw::post'],
        }
    }
    default: {
        # silently not supported
    }
}
