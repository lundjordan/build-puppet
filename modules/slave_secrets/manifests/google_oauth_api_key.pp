# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla..org/MPL/2.0/.

class slave_secrets::google_oauth_api_key($ensure=present) {
    include config
    include users::builder
    include dirs::builds

    $google_oauth_api_key = $::operatingsystem ? {
        windows => 'C:/builds/google-oauth-api.key',
        default => "/builds/google-oauth-api.key"
    }

    if ($ensure == 'present' and $config::install_google_oauth_api_key) {
        file {
            $google_oauth_api_key:
                content => secret("google_oauth_api_key"),
                owner  => $::users::builder::username,
                group  => $::users::builder::group,
                mode    => 0600,
                show_diff => false;
        }
    } else {
        file {
            $google_oauth_api_key:
                ensure => absent;
        }
    }
}
