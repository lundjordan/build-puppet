# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Mozilla build package source: https://wiki.mozilla.org/MozillaBuild
# MozillaBuildSetup-Latest.zip is manually repackaged using 7 zip
# It is repackaged because the original exe cannot be silently installed and when extracted charecters in the top level directories are not recognized by Windows

class packages::mozilla::mozilla_build {
    packages::pkgzip {"MozillaBuildSetup-Latest.zip":
        zip => "MozillaBuildSetup-Latest.zip",
        target_dir => 'C:\mozilla-build';
    }
    # Append needed directories to the Windows path variable
    windows_path {
        'c:/mozilla-build':
            ensure => present;
    }
    windows_path {
        'C:\mozilla-build\python':
            ensure => present;
    }
    windows_path {
        'C:\mozilla-build\python\scripts':
            ensure => present;
    }
    windows_path {
        'C:\mozilla-build\msys\bin':
            ensure => present;
    }
    windows_path {
        'C:\mozilla-build\C:\mozilla-build\vim\vim72':
            ensure => present;
    }
    windows_path {
        'C:\mozilla-build\wget':
            ensure => present;
    }
    windows_path {
        'C:\mozilla-build\info-zip':
            ensure => present;
    }
}
