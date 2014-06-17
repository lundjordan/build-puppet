class slaveapi::aws ($slaveapi_title='prod') {
    include ::config
    include users::builder

    # use the slaveapi user - cltbld instead of buildduty
    $user = $users::builder::username
    $group = $users::builder::group
    $home = $users::builder::home

    $basedir = "${slaveapi::base::root}/${slaveapi_title}"
    $aws_dst = "${basedir}/aws"
    $cloud_tools_dst = "${aws_dst}/aws/cloud-tools"
    $secrets_dst = "${aws_dst}/aws/secrets"
    $aws_bin_dst = "${aws_dst}/aws/bin"

    # initial file setup
    file {
        "${aws_dst}":
            ensure  => directory,
            mode    => 0755,
            owner => $user,
            group => $group;
        "${secrets_dst}":
            ensure => directory,
            mode => 0700,
            owner => $user,
            group => $group,
            require => File[$aws_dst];
        "${home}/.boto":
            mode      => 0600,
            owner     => $user,
            group     => $group,
            show_diff => false,
            content   => template("$module_name/dot_boto.erb");
        "${home}/.ssh/aws-ssh-key":
            mode      => 0600,
            owner     => $user,
            group     => $group,
            show_diff => false,
            content   => secret("aws_manager_ssh_key");
    }

    # cloud-tools repo
    mercurial::repo {
        "cloud-tools-${cloud_tools_dst}":
            hg_repo => "${config::cloud_tools_hg_repo}",
            dst_dir => $cloud_tools_dst,
            user    => $user,
            branch  => "${config::cloud_tools_hg_branch}",
            require => Python::Virtualenv[$basedir];
    }

    # cron tasks
    file {
        "/etc/cron.d/slaveapi-update-hg-cloud-tools":
            content => "*/5 * * * * ${user} cd ${cloud_tools_dst} && ${packages::mozilla::py27_mercurial::mercurial} pull -u\n";
    }
}

