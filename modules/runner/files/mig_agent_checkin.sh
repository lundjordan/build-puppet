#!/bin/bash
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# use sudo when we aren't running as root (i.e., on OS X)
if [ "$UID" != 0 ]; then
    PREFIX="sudo"
fi

# run mig-agent in checkin mode
$PREFIX /sbin/mig-agent -m agent-checkin || true
