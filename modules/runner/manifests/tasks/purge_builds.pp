# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Make sure runner runs at boot
class runner::tasks::purge_builds($runlevel=1, $required_space=10) {
    # Requires tools checked out
    include runner
    include runner::tasks::checkout_tools

    runner::task {
        "${runlevel}-purge_builds":
            content  => template("${module_name}/tasks/purge_builds.erb");
    }
}
