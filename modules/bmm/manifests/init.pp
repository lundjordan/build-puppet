# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
class bmm {
    include dirs::opt::bmm

    include bmm::httpd
    include bmm::tftpd
    include bmm::rsyslog

    include nrpe::check::procs_regex
    include nrpe::check::swap
    include nrpe::check::ntp_time
    include nrpe::check::ntp_peer
}
