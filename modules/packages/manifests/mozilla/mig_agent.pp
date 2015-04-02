# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
class packages::mozilla::mig_agent {
    # The mig-agent package does not start the agent automatically on install.
    # The agent needs to be invoked manually after install, by calling '/sbin/mig-agent'.
    # service files for (upstart|systemd|sysvinit) are created by the agent itself.
    # see doc at https://github.com/mozilla/mig/blob/master/doc/concepts.rst
    case $::operatingsystem {
        'CentOS', 'RedHat': {
            realize(Packages::Yumrepo['mig-agent'])
            package {
                'mig-agent':
                    ensure => '20150122+ad43a11.prod-1'
            }
        }
        'Ubuntu': {
            realize(Packages::Aptrepo['mig-agent'])
            package {
                'mig-agent':
                    ensure => '20150122+ad43a11.prod'
            }
        }
        default: {
            fail("mig is not supported on ${::operatingsystem}")
        }
    }
 }
