# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
class toplevel::slave::build inherits toplevel::slave {
    include dirs::tools
    include dirs::builds
    include dirs::builds::slave
    include dirs::builds::hg_shared
    include dirs::builds::git_shared
    include dirs::builds::tooltool_cache

    include users::builder

    include ntp::daemon
    include tweaks::nofile
    include tweaks::filesystem

    include nrpe
    include nrpe::check::buildbot
    include nrpe::check::ide_smart
    include nrpe::check::procs_regex
    include nrpe::check::child_procs_regex

    include packages::mozilla::git
    include packages::mozilla::py27_virtualenv
    include packages::mozilla::hgtool
    include packages::mozilla::gittool
    include packages::mozilla::retry
    include packages::patch

    include jacuzzi_metadata
    include aws::instance_storage

    ccache::ccache_dir {
        "/builds/ccache":
            maxsize => "10G",
            owner => $users::builder::username,
            group => $users::builder::group;
    }

    class {
        'slave_secrets':
            slave_type => 'build';
    }
}
