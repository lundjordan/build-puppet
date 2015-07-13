# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

class tweaks::windows_network_opt_netsh {
    # For 2008 refrence Bugs 1165314, 1166415, & 1168812
    # Netsh interface commands prove to be slightly problematic when executing through Puppet
    # When the command is executed it is executed in a 32 bit context which causes errors
    # To work around this the commands are being concated into bat file and then executed through a Scheduled task 
    # For additional info ref: https://bugzilla.mozilla.org/show_bug.cgi?id=1165567
    include dirs::etc
   
    $netsh_log   = "C:\\ProgramData\\PuppetLabs\\puppet\\var\\log\\netsh_error.log"
    $set_netsh   = 'set netcmd=C:\windows\System32\netsh.exe'
    $run_netsh   = "\n %netcmd%\n"
    $failed      = " failed with  exit code %errorlevel% "
    $ErrorCheck  = "If %errorlevel% neq 0 echo %netcmd%$failed>>$netsh_log\n"
    $QuotedLAC   = '"Local Area Connection"'
    $QuotedLAC_2 = '"Local Area Connection 2"'
    $NetTwBat    = "c:\\etc\\network_tweak.bat"    

    case $env_os_version {
        2008: { 
            concat { "$NetTwBat":
            }
            concat::fragment  { "network_tweak_bat_header" :
                target  => "$NetTwBat",
                content => template("tweaks/network_tweak.bat.erb"),
                order   => 01,
            }
            concat::fragment { "global_netdma" :
                target  => "$NetTwBat",
                content => "$set_netsh int tcp set global netdma=enabled$run_netsh $ErrorCheck",
                order   => 02,
            }
            concat::fragment  { "global_congestionprovider" :
                target  => "$NetTwBat",
                content => "$set_netsh int tcp set global congestionprovider=ctcp$run_netsh $ErrorCheck",
                order   => 04,
            }
            concat::fragment { "global_ecncapability" :
                target  => "$NetTwBat",
                content => "$set_netsh int tcp set global ecncapability=disabled$run_netsh $ErrorCheck",
                order   => 05
            }
            concat::fragment { "heuristics" :
                target  => "$NetTwBat",
                content => "$set_netsh int tcp set heuristics disabled$run_netsh $ErrorCheck",
                order   => 06,
            }
            concat::fragment { "local_area_mtu" :
                target  => "$NetTwBat",
                content => "$set_netsh int ipv4 set subinterface $QuotedLAC mtu=1500 store=persistent$run_netsh $ErrorCheck",
                order   => 07,
            }
            concat::fragment { "local_area2_mtu" :
                target  => "$NetTwBat",
                content => "$set_netsh int ipv4 set subinterface $QuotedLAC_2 mtu=1500 store=persistent$run_netsh $ErrorCheck",
                order   => 08,
            }
            concat::fragment { "global autotuning" :
                target  => "$NetTwBat",
                content => "$set_netsh int tcp set global autotuning=normal$run_netsh $ErrorCheck",
                order   => 09,
            }
            case $::fqdn {
                /.*\.releng\.(use1|usw2)\.mozilla\.com$/: {
                    concat::fragment { "global_rss" :
                        target  => "$NetTwBat",
                        content => "$set_netsh int tcp set global rss=enabled$run_netsh $ErrorCheck",
                        order   => 10,
                    }
                    concat::fragment { "chimney" :
                        target  => "$NetTwBat",
                        content => "$set_netsh int tcp set global chimney=disabled$run_netsh $ErrorCheck",
                        order   => 11,
                    }
                    concat::fragment { "global_dca" :
                        target  => "$NetTwBat",
                        content => "$set_netsh int tcp set global dca=disabled$run_netsh $ErrorCheck",
                        order   => 12,
                    }
                }
                default: {
                    concat::fragment { "global_dca" :
                        target  => "$NetTwBat",
                        content => "$set_netsh int tcp set global dca=enabled$run_netsh $ErrorCheck",
                        order   => 10,
                    }
                }
            }
            file {'C:/programdata/puppetagain/SchTsk_netsh.xml':
                content => template("tweaks/SchTsk_netsh.xml.erb"),
            }
            # Set up the schedule task
            exec { "SchTsk_netsh":
                command     => '"C:\Windows\system32\schtasks.exe" /Create  /XML "C:/programdata/puppetagain/SchTsk_netsh.xml" /TN SchTsk_netsh',
                require     => Concat["$NetTwBat"],
                subscribe   => File['C:/programdata/puppetagain/SchTsk_netsh.xml'],
                refreshonly => true,
            }
            # Execute schedule task
            exec { "network_tweak_bat" :
                command      => '"C:\Windows\system32\schtasks.exe" /Run /TN SchTsk_netsh',
                require      => [Concat::Fragment["global_dca"],
                                Exec["SchTsk_netsh"]
                                ],   
                subscribe   => Concat["$NetTwBat"],
                refreshonly => true,
            }
            # Because this is being executed through a schedule task failures are not passed back to Puppet 
            # This log is generated by failures from the concatted batch file 
            # It's existence means at least one failure occurred
            # See the log file itself to view failures
            file {'C:/etc/netsh_check.bat':
                content => template("tweaks/netsh_check.bat.erb"),
                require     => Class[dirs::etc],
            }
            exec { "netsh_error_check" :
                command     => "C:/etc/netsh_check.bat",
                returns     => 1,
                subscribe   => Exec["network_tweak_bat"],
                refreshonly => true,
            }
        }
        default: {
            fail("Network optimization has not been configured for this platform")
        }
    }
}

























