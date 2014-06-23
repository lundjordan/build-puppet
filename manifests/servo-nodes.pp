# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

## builders

node /servo-.*\.build\.servo\.aws-.*\.mozilla\.com/ {
    # Make sure we get our /etc/hosts set up
    $slave_trustlevel = "prod"
    include toplevel::slave::releng::build::mock
}

node /servo-.*\.build\.servo\.releng\.(use1|usw2)\.mozilla.com/ {
    # Make sure we get our /etc/hosts set up
    $slave_trustlevel = "prod"
    include toplevel::slave::releng::build::mock
}

node /servo-lion-r5-\d+\.build\.servo\.releng\.scl3\.mozilla\.com/ {
    $slave_trustlevel = "prod"
    include toplevel::slave::releng::build::standard
}


## puppetmasters

node /servo-puppet\d+\.srv\.servo\.releng\.use1\.mozilla\.com/ {
    include toplevel::server::puppetmaster
}


## buildbot masters

node "buildbot-master-servo-01.srv.servo.releng.use1.mozilla.com" {
    include toplevel::server::buildmaster::servo
}
