#! /bin/bash

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# You can set PUPPET_SERVER before running this script to use a server other
# than 'puppet'

REBOOT_FLAG_FILE="/REBOOT_AFTER_PUPPET"
OS=`facter operatingsystem`
case "$OS" in
    Darwin) ROOT=/var/root ;;
    *) ROOT=/root ;;
esac

# wait for all networking services to become available.  This prevents a race condition with network availablity
# use ipconfig waitall for darwin and do nothing for linux
if [ ${OS} = "Darwin" ]; then
	ipconfig waitall
fi

# determine interactivity based on the presence of a deploypass file
[ -f $ROOT/deploypass ] && interactive=false || interactive=true

hang() {
    echo "${@}"
    while true; do sleep 60; done
}

if ! $interactive; then
    echo "Puppetize output is in $ROOT/puppetize.log"
    exec >$ROOT/puppetize.log 2>&1
fi

if [ -f $ROOT/deploypass ]; then
    deploypass=$(<$ROOT/deploypass)
else
    $interactive || hang "No $ROOT/deploypass and not connected to a tty"
fi

while true; do
    FQDN=`facter fqdn`
    if [ -z $FQDN ]; then
        $interactive && exit 1
        echo "Failed to determine FQDN; re-trying after delay"
        sleep 60
    else
        break
    fi
done

# set up and clean up
mkdir -p /var/lib/puppet/ssl/private_keys || exit 1
mkdir -p /var/lib/puppet/ssl/certs || exit 1
rm -f /var/lib/puppet/ssl/private_keys/$FQDN.pem || exit 1
rm -f /var/lib/puppet/ssl/certs/$FQDN.pem || exit 1
rm -f /var/lib/puppet/ssl/certs/ca.pem || exit 1

# try to get the certs; note that we can't check the SSL cert here, because it
# is self-signed by whatever puppet master we find; the SSL is mainly to
# encipher the password, so this isn't a big problem.  We do this in Python since
# curl and wget are not installed everywhere by default.
while true; do
    https_proxy= python <<EOF
import urllib2, getpass, ssl
deploypass="""$deploypass"""
puppet_server="${PUPPET_SERVER:-puppet}"
print "Contacting puppet server %s" % (puppet_server,)
if not deploypass:
    deploypass = getpass.getpass('deploypass: ')
password_mgr = urllib2.HTTPPasswordMgrWithDefaultRealm()
password_mgr.add_password(None, 'https://'+puppet_server, 'deploy', deploypass)
handlers = [urllib2.HTTPBasicAuthHandler(password_mgr)]
try:
    # on Pythons that support it, add an SSL context
    context = ssl._create_unverified_context()
    sslhandler = urllib2.HTTPSHandler(context=context)
    handlers.insert(0, sslhandler)
except AttributeError:
    pass
opener = urllib2.build_opener(*handlers)
data = opener.open('https://%s/deploy/getcert.cgi' % (puppet_server,)).read()
open("$ROOT/certs.sh", "w").write(data)
EOF
    if [ $? -ne 0 ]; then
        $interactive && exit 1
        echo "Failed to get certificates; re-trying after delay"
        sleep 60
    else
        break
    fi
done

# make sure the time is set correctly, or SSL will fail, badly.
case "$OS" in
    Darwin)
        if launchctl list org.ntp.ntpd > /dev/null 2>&1 ; then
            launchctl unload /System/Library/LaunchDaemons/org.ntp.ntpd.plist
        fi
        ntpdate pool.ntp.org
        launchctl load -w /System/Library/LaunchDaemons/org.ntp.ntpd.plist
        ;;

    CentOS)
        ntprunning=`ps ax | grep ntpd | grep -v grep`
        [ -n "$ntprunning" ] && /sbin/service ntpd stop
        /usr/sbin/ntpdate pool.ntp.org
        [ -n "$ntprunning" ] && /sbin/service ntpd start
        ;;

    Ubuntu)
        # no ntp service to worry about
        /usr/sbin/ntpdate pool.ntp.org
        ;;
esac

# source the shell script we got from the deploy run
cd /var/lib/puppet/ssl || exit 1
. $ROOT/certs.sh

# sanity check
if ! [ -e private_keys/$FQDN.pem -a -e certs/$FQDN.pem -a -e certs/ca.pem ]; then
    find . -type f
    hang "Got incorrect certificates (!?)"
fi

cd /

if ! $interactive; then
    if test -f $ROOT/deploypass; then
        echo "securely removing deploypass"
        case "$OS" in
            CentOS)
                shred -u -n 7 -z $ROOT/deploypass || hang
                # kernel command line is helpfully logged here!
                for ANACONDA_LOG in /var/log/anaconda.{log,syslog}; do
                    if [ -f $ANACONDA_LOG ]; then
                        shred -u -n 7 -z $ANACONDA_LOG || hang
                    fi
                done
                ;;

            Ubuntu)
                shred -u -n 7 -z $ROOT/deploypass || hang
                ;;
            Darwin)
                srm -zmf $ROOT/deploypass || hang
                ;;
        esac
    fi
fi

if $interactive; then
    echo "Certificates are ready; run puppet now."
    exit 0
fi

run_puppet() {
    puppet_server="${PUPPET_SERVER:-puppet}"
    echo $"Running puppet agent against server '$puppet_server'"
    # this includes:
    # --pluginsync so that we download plugins on the first run, as they may be required
    # --ssldir=/var/lib/puppet/ssl because it defaults to /etc/puppet/ssl on OS X
    # FACTER_PUPPETIZING so that the manifests know this is a first run of puppet
    PUPPET_OPTIONS="--onetime --no-daemonize --logdest=console --logdest=syslog --color=false --ssldir=/var/lib/puppet/ssl --pluginsync --detailed-exitcodes --server $puppet_server"
    export FACTER_PUPPETIZING=true

    # check for 'err:' in the output; this catches errors even
    # when the puppet exit status is incorrect.
    tmp=`mktemp /tmp/puppet-outputXXXXXX`
    [ -f "$tmp" ] || hang "mktemp failed"
    /usr/bin/puppet agent $PUPPET_OPTIONS > $tmp 2>1
    retval=$?
    # just in case, if there were any errors logged, flag it as an error run
    if grep -q "^Error:" $tmp
    then
        retval=1
    fi

    rm $tmp
    case $retval in
        0|2) return 0;;
        *) return 1;;
    esac
}
while ! run_puppet; do
    echo "Puppet run failed; re-trying after 10m"
    sleep 600
done

# don't run puppetize at boot anymore
case "$OS" in
    CentOS)
        grep -v puppetize /etc/rc.d/rc.local > /etc/rc.d/rc.local~
        mv /etc/rc.d/rc.local{~,}
        ;;

    Darwin)
        rm /Library/LaunchDaemons/org.mozilla.puppetize.plist*
        ;;

    Ubuntu)
        grep -v puppetize /etc/rc.local > /etc/rc.local~
        mv /etc/rc.local{~,}
        ;;
esac

# record the installation date (note that this won't appear anywhere on Darwin)
echo "System Installed:" `date` >> /etc/issue

# execute post puppet custom code in the same process to allow the script
# acccessing not exported variables
if [ -f "$ROOT/post-puppetize-hook.sh" ]; then
    echo "Sourcing $ROOT/post-puppetize-hook.sh"
    . "$ROOT/post-puppetize-hook.sh"
fi

# Mandatory reboot after non-interactive puppetizing
# use post-puppetize-hook.sh with 'exit 0' to prevent this
rm -f "${REBOOT_FLAG_FILE}"
echo "Rebooting now"
sleep 10
reboot

