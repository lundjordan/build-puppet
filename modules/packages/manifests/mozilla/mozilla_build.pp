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
    # Update hg's Path.rc to point to a valid path
    file {
        "C:/mozilla-build/hg/hgrc.d/Paths.rc":
            replace => true,
            source  => "puppet:///modules/packages/Paths.rc";
    }
    # Currently Buildbot looks for python27 on Windows slaves.
    # This will need to be revisited when Python is updated in the Mozillabuild package.
    file {
        'C:/mozilla-build/python27':
            ensure => link,
            links  => follow,
            target => 'C:/mozilla-build/python';
    }
    # When buildbot looks for nsis, version 3.0a2 causes an error "Error initalizing CEXEBuild: can't open file: integer expression expected"
    # Reference https://bugzilla.mozilla.org/show_bug.cgi?id=989531
    # Temporary work around is to move version 3.0a2, so that 2.46u is used  
    exec {"move_nsis_3_0a2":
        command => 'C:\mozilla-build\msys\bin\mv.exe  C:\mozilla-build\nsis-3.0a2 C:\mozilla-build\HOLDnsis-3.0a2 /y',
        creates => 'C:\mozilla-build\HOLDnsis-3.0a2',
        require => Packages::Pkgzip["MozillaBuildSetup-Latest.zip"];
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
