#!/usr/bin/perl
# nagios: +epn
# ^^this must be the second line of the perlscript.
# '# nagios: +epn' enables embedded perl, '# nagios: -epn' disables it.
############################## check_snmp_int ##############
# Version : 1.4.6
# Date : April 23 2007
# Author  : Patrick Proy ( patrick at proy.org )
# Help : http://nagios.manubulon.com
# Licence : GPL - http://www.fsf.org/licenses/gpl.txt
# Contrib : J. Jungmann, S. Probst, R. Leroy, M. Berger
# TODO :
# Check isdn "dormant" state
# Maybe put base directory for performance as an option
#################################################################
#
# Help : ./check_snmp_int.pl -h
#
use warnings;
use strict;

my $check = check_snmp_int->new();
exit;

package check_snmp_int;
use warnings;
use strict;
use Net::SNMP qw(oid_lex_sort);
use Getopt::Long;
use lib "/omd/sites/it/lib/nagios/plugins";
use utils qw(%ERRORS $TIMEOUT);

sub new {
    my $class = shift;
    my $self  = {
############### BASE DIRECTORY FOR TEMP FILE ########
        o_base_dir   => "/tmp/tmp_Nagios_int.",
        file_history => 200,                      # number of data to keep in files.

        # SNMP Datas
        inter_table        => '.1.3.6.1.2.1.2.2.1',
        index_table        => '1.3.6.1.2.1.2.2.1.1',
        descr_table        => '1.3.6.1.2.1.2.2.1.2',
        oper_table         => '1.3.6.1.2.1.2.2.1.8.',
        admin_table        => '1.3.6.1.2.1.2.2.1.7.',
        speed_table        => '1.3.6.1.2.1.2.2.1.5.',
        in_octet_table     => '1.3.6.1.2.1.2.2.1.10.',
        in_octet_table_64  => '1.3.6.1.2.1.31.1.1.1.6.',
        in_error_table     => '1.3.6.1.2.1.2.2.1.14.',
        in_discard_table   => '1.3.6.1.2.1.2.2.1.13.',
        out_octet_table    => '1.3.6.1.2.1.2.2.1.16.',
        out_octet_table_64 => '1.3.6.1.2.1.31.1.1.1.10.',
        out_error_table    => '1.3.6.1.2.1.2.2.1.20.',
        out_discard_table  => '1.3.6.1.2.1.2.2.1.19.',

        status => { 1 => 'UP', 2 => 'DOWN', 3 => 'TESTING', 4 => 'UNKNOWN', 5 => 'DORMANT', 6 => 'NotPresent', 7 => 'lowerLayerDown' },

        # Globals
        Version => '1.4.6',

        # Standard options
        o_host    => undef,    # hostname
        o_port    => 161,      # port
        o_descr   => undef,    # description filter
        o_help    => undef,    # wan't some help ?
        o_admin   => undef,    # admin status instead of oper
        o_inverse => undef,    # Critical when up
        o_verb    => undef,    # verbose mode
        o_version => undef,    # print version
        o_noreg   => undef,    # Do not use Regexp for name
        o_short   => undef,    # set maximum of n chars to be displayed
        o_label   => undef,    # add label before speed (in, out, etc...).
        o_index   => undef,    # index of interface
        o_test    => undef,    # Test mode

        # Performance data options
        o_perf  => undef,      # Output performance data
        o_perfe => undef,      # Output discard/error also in perf data
        o_perfs => undef,      # include speed in performance output (-S)
        o_perfp => undef,      # output performance data in % of max speed (-y)
        o_perfr => undef,      # output performance data in bits/s or Bytes/s (-Y)

        # Speed/error checks
        o_checkperf     => undef,    # checks in/out/err/disc values
        o_delta         => 300,      # delta of time of perfcheck (default 5min)
        o_ext_checkperf => undef,    # extended perf checks (+error+discard)
        o_warn_opt      => undef,    # warning options
        o_crit_opt      => undef,    # critical options
        o_kbits         => undef,    # Warn and critical in Kbits instead of KBytes
        o_warn          => [],       # warning levels of perfcheck
        o_crit          => [],       # critical levels of perfcheck
        o_highperf      => undef,    # Use 64 bits counters
        o_meg           => undef,    # output in MBytes or Mbits (-M)
        o_gig           => undef,    # output in GBytes or Gbits (-G)
        o_prct          => undef,    # output in % of max speed  (-u)

        o_timeout => undef,          # Timeout (Default 5)

        # SNMP Message size parameter (Makina Corpus contrib)
        o_octetlength => undef,

        # Login options specific
        o_community => undef,        # community
        o_version2  => undef,        #use snmp v2c
        o_login     => undef,        # Login for snmpv3
        o_passwd    => undef,        # Pass for snmpv3
        v3protocols => undef,        # V3 protocol list.
        o_authproto => 'md5',        # Auth protocol
        o_privproto => 'des',        # Priv protocol
        o_privpass  => undef,        # priv password

        # Readable names for counters (M. Berger contrib)
        countername        => [ "in=", "out=", "errors-in=", "errors-out=", "discard-in=", "discard-out=" ],
        checkperf_out_desc => undef,
    };
    bless( $self, $class );

########## MAIN #######

    $self->check_options();

    # Check gobal timeout if snmp screws up
    if( defined($TIMEOUT) ) {
        $self->verb("Alarm at $TIMEOUT + 5");
        alarm( $TIMEOUT + 5 );
    }
    else {
        $self->verb("no timeout defined : $self->{o_timeout} + 10");
        alarm( $self->{o_timeout} + 10 );
    }

    $SIG{'ALRM'} = sub {
        print "No answer from host\n";
        exit $ERRORS{"UNKNOWN"};
    };

    # Connect to host
    my( $session, $error );
    if( defined( $self->{o_login} ) && defined( $self->{o_passwd} ) ) {

        # SNMPv3 login
        if( !defined( $self->{o_privpass} ) ) {
            $self->verb("SNMPv3 AuthNoPriv login : $self->{o_login}, $self->{o_authproto}");
            ( $session, $error ) = Net::SNMP->session(
                -hostname     => $self->{o_host},
                -version      => '3',
                -port         => $self->{o_port},
                -username     => $self->{o_login},
                -authpassword => $self->{o_passwd},
                -authprotocol => $self->{o_authproto},
                -timeout      => $self->{o_timeout} );
        }
        else {
            $self->verb("SNMPv3 AuthPriv login : $self->{o_login}, $self->{o_authproto}, $self->{o_privproto}");
            ( $session, $error ) = Net::SNMP->session(
                -hostname     => $self->{o_host},
                -version      => '3',
                -username     => $self->{o_login},
                -port         => $self->{o_port},
                -authpassword => $self->{o_passwd},
                -authprotocol => $self->{o_authproto},
                -privpassword => $self->{o_privpass},
                -privprotocol => $self->{o_privproto},
                -timeout      => $self->{o_timeout} );
        }
    }
    else {
        if( defined( $self->{o_version2} ) ) {

            # SNMPv2c Login
            $self->verb("SNMP v2c login");
            ( $session, $error ) = Net::SNMP->session(
                -hostname  => $self->{o_host},
                -version   => 2,
                -community => $self->{o_community},
                -port      => $self->{o_port},
                -timeout   => $self->{o_timeout} );
        }
        else {

            # SNMPV1 login
            $self->verb("SNMP v1 login");
            ( $session, $error ) = Net::SNMP->session(
                -hostname  => $self->{o_host},
                -community => $self->{o_community},
                -port      => $self->{o_port},
                -timeout   => $self->{o_timeout} );
        }
    }
    if( !defined($session) ) {
        printf( "ERROR opening session: %s.\n", $error );
        exit $ERRORS{"UNKNOWN"};
    }

    if( defined( $self->{o_octetlength} ) ) {
        my $oct_resultat = undef;
        my $oct_test     = $session->max_msg_size();
        $self->verb(" actual max octets:: $oct_test");
        $oct_resultat = $session->max_msg_size( $self->{o_octetlength} );
        if( !defined($oct_resultat) ) {
            printf( "ERROR: Session settings : %s.\n", $session->error );
            $session->close;
            exit $ERRORS{"UNKNOWN"};
        }
        $oct_test = $session->max_msg_size();
        $self->verb(" new max octets:: $oct_test");
    }

    # Get desctiption table
    my $resultat = $session->get_table( Baseoid => $self->{descr_table} );

    if( !defined($resultat) ) {
        printf( "ERROR: Description table : %s.\n", $session->error );
        $session->close;
        exit $ERRORS{"UNKNOWN"};
    }
    my @tindex = undef;
    my @oids   = undef;
    my @descr  = undef;
    my( @oid_perf, @oid_perf_outoct, @oid_perf_inoct, @oid_perf_inerr, @oid_perf_outerr, @oid_perf_indisc, @oid_perf_outdisc ) = ( undef, undef, undef, undef, undef, undef, undef );
    my @oid_speed = undef;
    my $num_int   = 0;

    # Change to 64 bit counters if option is set :
    if( defined( $self->{o_highperf} ) ) {
        $self->{out_octet_table} = $self->{out_octet_table_64};
        $self->{in_octet_table}  = $self->{in_octet_table_64};
    }
## Test for interface names/index
    if( $self->{o_test} ) {
        foreach my $key ( oid_lex_sort( keys %$resultat ) ) {
            my $index;
            ( $index = $key ) =~ s/.*\.(\d+)/$1/g;
            print "index: $index  interface $$resultat{$key} \n";
        }
        exit 0;
    }

    # Select interface by regexp of exact match
    # and put the oid to query in an array

    $self->verb("Filter : $self->{o_descr}") if( defined( $self->{o_descr} ) );

    #$self->verb("Test : $self->{o_test}")if (defined($self->{o_test}));
    foreach my $key ( oid_lex_sort( keys %$resultat ) ) {
        $self->verb("OID : $key, Desc : $$resultat{$key}");
        my $test;

        # test by regexp or exact match or index
        if( $self->{o_noreg} ) {
            $test = $$resultat{$key} eq $self->{o_descr};
        }
        elsif ( $self->{o_index} ) {
            $test = $key =~ /.*\.$self->{o_index}$/;
        }
        else {
            $test = $$resultat{$key} =~ /$self->{o_descr}/;
        }

        $self->verb("test value_ $test");
        if($test) {

            # get the index number of the interface
            my @oid_list = split( /\./, $key );
            $tindex[$num_int] = pop(@oid_list);

            # get the full description
            $descr[$num_int] = $$resultat{$key};

            # Get rid of special caracters (specially for Windows)
            $descr[$num_int] =~ s/[[:cntrl:]]//g;

            # put the admin or oper oid in an array
            $oids[$num_int]
                = defined( $self->{o_admin} )
                ? $self->{admin_table} . $tindex[$num_int]
                : $self->{oper_table} . $tindex[$num_int];

            # Put the performance oid
            if( defined( $self->{o_perf} ) || defined( $self->{o_checkperf} ) ) {
                $oid_perf_inoct[$num_int]  = $self->{in_octet_table} . $tindex[$num_int];
                $oid_perf_outoct[$num_int] = $self->{out_octet_table} . $tindex[$num_int];
                $oid_speed[$num_int]       = $self->{speed_table} . $tindex[$num_int];
                if( defined( $self->{o_ext_checkperf} ) || defined( $self->{o_perfe} ) ) {
                    $oid_perf_indisc[$num_int]  = $self->{in_discard_table} . $tindex[$num_int];
                    $oid_perf_outdisc[$num_int] = $self->{out_discard_table} . $tindex[$num_int];
                    $oid_perf_inerr[$num_int]   = $self->{in_error_table} . $tindex[$num_int];
                    $oid_perf_outerr[$num_int]  = $self->{out_error_table} . $tindex[$num_int];
                }
            }
            $self->verb("Name : $descr[$num_int], Index : $tindex[$num_int]");
            $num_int++;
        }
    }

    # No interface found -> error
    if( $num_int == 0 ) { print "ERROR : Unknown interface $self->{o_descr}\n"; exit $ERRORS{"UNKNOWN"}; }

    my( $result, $resultf ) = ( undef, undef );

    # Get the requested oid values
    $result = $session->get_request( Varbindlist => \@oids );
    if( !defined($result) ) {
        printf( "ERROR: Status table : %s.\n", $session->error );
        $session->close;
        exit $ERRORS{"UNKNOWN"};
    }

    # Get the perf value if -f (performance) option defined or -k (check bandwidth)
    if( defined( $self->{o_perf} ) || defined( $self->{o_checkperf} ) ) {
        @oid_perf = ( @oid_perf_outoct, @oid_perf_inoct, @oid_perf_inerr, @oid_perf_outerr, @oid_perf_indisc, @oid_perf_outdisc, @oid_speed );
        $resultf = $session->get_request( Varbindlist => \@oid_perf );
        if( !defined($resultf) ) {
            printf( "ERROR: Statistics table : %s.\n", $session->error );
            $session->close;
            exit $ERRORS{"UNKNOWN"};
        }
    }

    $session->close;

    my $num_ok            = 0;
    my @checkperf_out     = undef;
    my @checkperf_out_raw = undef;
### Bandwidth test variables
    my $temp_file_name;
    my( $return, @file_values ) = ( undef, undef );
    my $n_rows        = 0;
    my $n_items_check = ( defined( $self->{o_ext_checkperf} ) ) ? 7 : 3;
    my $timenow       = time;
    my $trigger       = $timenow - ( $self->{o_delta} - ( $self->{o_delta} / 10 ) );
    my $trigger_low   = $timenow - 3 * $self->{o_delta};
    my( $old_value, $old_time ) = undef;
    my $speed_unit = undef;

    # define the OK value depending on -i option
    my $ok_val = defined( $self->{o_inverse} ) ? 2 : 1;
    my $final_status = 0;
    my( $print_out, $perf_out ) = ( undef, undef );

    # make all checks and output for all interfaces
    for ( my $i = 0; $i < $num_int; $i++ ) {
        $print_out .= ", " if( defined($print_out) );
        $perf_out  .= " "  if( defined($perf_out) );
        my $usable_data = 1;

        # Get the status of the current interface
        my $int_status
            = defined( $self->{o_admin} )
            ? $$result{ $self->{admin_table} . $tindex[$i] }
            : $$result{ $self->{oper_table} . $tindex[$i] };

        # Make the bandwith & error checks if necessary
        if( defined( $self->{o_checkperf} ) && $int_status == 1 ) {
            $temp_file_name = $descr[$i];
            $temp_file_name =~ s/[ ;\/]/_/g;
            $temp_file_name = $self->{o_base_dir} . $self->{o_host} . "." . $temp_file_name;

            # First, read entire file
            my @ret_array = $self->read_file( $temp_file_name, $n_items_check );
            $return = shift(@ret_array);
            $n_rows = shift(@ret_array);
            if( $n_rows != 0 ) { @file_values = @ret_array }
            $self->verb("File read returns : $return with $n_rows rows");
            $self->verb("Interface speed : $$resultf{$oid_speed[$i]}");

            #make the checks if the file is OK
            if( $return == 0 ) {
                my $j = $n_rows - 1;
                @checkperf_out     = undef;
                @checkperf_out_raw = undef;
                do {
                    if( $file_values[$j][0] < $trigger ) {
                        if( $file_values[$j][0] > $trigger_low ) {

                            # Define the speed metric ( K | M | G ) (Bits|Bytes) or %
                            my $speed_metric = undef;
                            if( defined( $self->{o_prct} ) ) {    # in % of speed
                                                                  # Speed is in bits/s, calculated speed is in Bytes/s
                                $speed_metric = $$resultf{ $oid_speed[$i] } / 800;
                                $speed_unit   = "%";
                            }
                            else {
                                if( defined( $self->{o_kbits} ) ) {    # metric in bits
                                    if( defined( $self->{o_meg} ) ) {    # in Mbit/s = 1000000 bit/s
                                        $speed_metric = 125000;          #  (1000/8) * 1000
                                        $speed_unit   = "Mbps";
                                    }
                                    elsif ( defined( $self->{o_gig} ) ) {    # in Gbit/s = 1000000000 bit/s
                                        $speed_metric = 125000000;           #  (1000/8) * 1000 * 1000
                                        $speed_unit   = "Gbps";
                                    }
                                    else {                                   # in Kbits
                                        $speed_metric = 125;                 #  ( 1000/8 )
                                        $speed_unit   = "Kbps";
                                    }
                                }
                                else {                                       # metric in byte
                                    if( defined( $self->{o_meg} ) ) {        # in Mbits
                                        $speed_metric = 1048576;             # 1024^2
                                        $speed_unit   = "MBps";
                                    }
                                    elsif ( defined( $self->{o_gig} ) ) {    # in Mbits
                                        $speed_metric = 1073741824;          # 1024^3
                                        $speed_unit   = "GBps";
                                    }
                                    else {
                                        $speed_metric = 1024;                # 1024^3
                                        $speed_unit   = "KBps";
                                    }
                                }
                            }

                            # check if the counter is back to 0 after 2^32 / 2^64.
                            # First set the modulus depending on highperf counters or not
                            my $overfl_mod = defined( $self->{o_highperf} ) ? 18446744073709551616 : 4294967296;

                            # Check counter (s)
                            my $overfl = ( $$resultf{ $oid_perf_inoct[$i] } >= $file_values[$j][1] ) ? 0 : $overfl_mod;
                            $checkperf_out_raw[0] = ( ( $overfl + $$resultf{ $oid_perf_inoct[$i] } - $file_values[$j][1] ) / ( $timenow - $file_values[$j][0] ) );
                            $checkperf_out[0] = $checkperf_out_raw[0] / $speed_metric;

                            $overfl = ( $$resultf{ $oid_perf_outoct[$i] } >= $file_values[$j][2] ) ? 0 : $overfl_mod;
                            $checkperf_out_raw[1] = ( ( $overfl + $$resultf{ $oid_perf_outoct[$i] } - $file_values[$j][2] ) / ( $timenow - $file_values[$j][0] ) );
                            $checkperf_out[1] = $checkperf_out_raw[1] / $speed_metric;

                            if( defined( $self->{o_ext_checkperf} ) ) {
                                $checkperf_out[2] = ( ( $$resultf{ $oid_perf_inerr[$i] } - $file_values[$j][3] ) /   ( $timenow - $file_values[$j][0] ) ) * 60;
                                $checkperf_out[3] = ( ( $$resultf{ $oid_perf_outerr[$i] } - $file_values[$j][4] ) /  ( $timenow - $file_values[$j][0] ) ) * 60;
                                $checkperf_out[4] = ( ( $$resultf{ $oid_perf_indisc[$i] } - $file_values[$j][5] ) /  ( $timenow - $file_values[$j][0] ) ) * 60;
                                $checkperf_out[5] = ( ( $$resultf{ $oid_perf_outdisc[$i] } - $file_values[$j][6] ) / ( $timenow - $file_values[$j][0] ) ) * 60;
                            }
                        }
                    }
                    $j--;
                } while ( ( $j >= 0 ) && ( !defined( $checkperf_out[0] ) ) );
            }

            # Put the new values in the array and write the file
            $file_values[$n_rows][0] = $timenow;
            $file_values[$n_rows][1] = $$resultf{ $oid_perf_inoct[$i] };
            $file_values[$n_rows][2] = $$resultf{ $oid_perf_outoct[$i] };
            if( defined( $self->{o_ext_checkperf} ) ) {    # Add other values (error & disc)
                $file_values[$n_rows][3] = $$resultf{ $oid_perf_inerr[$i] };
                $file_values[$n_rows][4] = $$resultf{ $oid_perf_outerr[$i] };
                $file_values[$n_rows][5] = $$resultf{ $oid_perf_indisc[$i] };
                $file_values[$n_rows][6] = $$resultf{ $oid_perf_outdisc[$i] };
            }
            $n_rows++;
            $return = $self->write_file( $temp_file_name, $n_rows, $n_items_check, @file_values );
            $self->verb("Write file returned : $return");

            # Print the basic status
            if( defined( $self->{o_short} ) ) {
                my $short_desc = undef;
                if( $self->{o_short} < 0 ) { $short_desc = substr( $descr[$i], $self->{o_short} ); }
                else { $short_desc = substr( $descr[$i], 0, $self->{o_short} ); }
                $print_out .= sprintf( "%s:%s", $short_desc, $self->{status}->{$int_status} );
                $descr[$i] = $short_desc;
            }
            else {
                $print_out .= sprintf( "%s:%s", $descr[$i], $self->{status}->{$int_status} );
            }
            if( $return != 0 ) {    # On error writing, return Unknown status
                $final_status = 3;
                $print_out .= " !!Unable to write file " . $temp_file_name . " !! ";
            }

            # print the other checks if it was calculated
            if( defined( $checkperf_out[0] ) ) {
                $print_out .= " (";

                # check 2 or 6 values depending on ext_check_perf
                my $num_checkperf = ( defined( $self->{o_ext_checkperf} ) ) ? 6 : 2;
                for ( my $l = 0; $l < $num_checkperf; $l++ ) {

                    # Set labels if needed
                    $self->{checkperf_out_desc} = ( defined( $self->{o_label} ) ) ? $self->{countername}->[$l] : "";
                    $self->verb("Interface $i, check $l : $checkperf_out[$l]");
                    if( $l != 0 ) { $print_out .= "/"; }
                    if( ( $self->{o_crit}->[$l] != 0 ) && ( $checkperf_out[$l] > $self->{o_crit}->[$l] ) ) {
                        $final_status = 2;
                        $print_out .= sprintf( "CRIT %s%.1f", $self->{checkperf_out_desc}, $checkperf_out[$l] );
                    }
                    elsif ( ( $self->{o_warn}->[$l] != 0 ) && ( $checkperf_out[$l] > $self->{o_warn}->[$l] ) ) {
                        $final_status = ( $final_status == 2 ) ? 2 : 1;
                        $print_out .= sprintf( "WARN %s%.1f", $self->{checkperf_out_desc}, $checkperf_out[$l] );
                    }
                    else {
                        $print_out .= sprintf( "%s%.1f", $self->{checkperf_out_desc}, $checkperf_out[$l] );
                    }
                    if( $l == 0 || $l == 1 ) { $print_out .= $speed_unit; }
                }
                $print_out .= ")";
            }
            else {    # Return unknown when no data
                $print_out .= " No usable data on file (" . $n_rows . " rows) ";
                $final_status = 3;
                $usable_data  = 0;
            }
        }
        else {
            if( defined( $self->{o_short} ) ) {
                my $short_desc = undef;
                if( $self->{o_short} < 0 ) { $short_desc = substr( $descr[$i], $self->{o_short} ); }
                else { $short_desc = substr( $descr[$i], 0, $self->{o_short} ); }
                $print_out .= sprintf( "%s:%s", $short_desc, $self->{status}->{$int_status} );
                $descr[$i] = $short_desc;
            }
            else {
                $print_out .= sprintf( "%s:%s", $descr[$i], $self->{status}->{$int_status} );
            }
        }

        # Get rid of special caracters for performance in description
        $descr[$i] =~ s/'\/\(\)/_/g;
        if( $int_status == $ok_val ) {
            $num_ok++;
        }
        if( ( $int_status == 1 ) && defined( $self->{o_perf} ) ) {
            if( defined( $self->{o_perfp} ) ) {    # output in % of speed
                if( $usable_data == 1 ) {
                    $perf_out .= "'" . $descr[$i] . "_in_prct'=";
                    $perf_out .= sprintf( "%.0f", $checkperf_out_raw[0] * 800 / $$resultf{ $oid_speed[$i] } ) . "%;";
                    $perf_out .= ( $self->{o_warn}->[0] != 0 ) ? $self->{o_warn}->[0] . ";" : ";";
                    $perf_out .= ( $self->{o_crit}->[0] != 0 ) ? $self->{o_crit}->[0] . ";" : ";";
                    $perf_out .= "0;100 ";
                    $perf_out .= "'" . $descr[$i] . "_out_prct'=";
                    $perf_out .= sprintf( "%.0f", $checkperf_out_raw[1] * 800 / $$resultf{ $oid_speed[$i] } ) . "%;";
                    $perf_out .= ( $self->{o_warn}->[1] != 0 ) ? $self->{o_warn}->[1] . ";" : ";";
                    $perf_out .= ( $self->{o_crit}->[1] != 0 ) ? $self->{o_crit}->[1] . ";" : ";";
                    $perf_out .= "0;100 ";
                }
            }
            elsif ( defined( $self->{o_perfr} ) ) {    # output in bites or Bytes /s
                if( $usable_data == 1 ) {
                    if( defined( $self->{o_kbits} ) ) {    # bps
                                                           # put warning and critical levels into bps or Bps
                        my $warn_factor = ( defined( $self->{o_meg} ) ) ? 1000000 : ( defined( $self->{o_gig} ) ) ? 1000000000 : 1000;
                        $perf_out .= "'" . $descr[$i] . "_in_bps'=";
                        $perf_out .= sprintf( "%.0f", $checkperf_out_raw[0] * 8 ) . ";";
                        $perf_out .= ( $self->{o_warn}->[0] != 0 ) ? $self->{o_warn}->[0] * $warn_factor . ";" : ";";
                        $perf_out .= ( $self->{o_crit}->[0] != 0 ) ? $self->{o_crit}->[0] * $warn_factor . ";" : ";";
                        $perf_out .= "0;" . $$resultf{ $oid_speed[$i] } . " ";
                        $perf_out .= "'" . $descr[$i] . "_out_bps'=";
                        $perf_out .= sprintf( "%.0f", $checkperf_out_raw[1] * 8 ) . ";";
                        $perf_out .= ( $self->{o_warn}->[1] != 0 ) ? $self->{o_warn}->[1] * $warn_factor . ";" : ";";
                        $perf_out .= ( $self->{o_crit}->[1] != 0 ) ? $self->{o_crit}->[1] * $warn_factor . ";" : ";";
                        $perf_out .= "0;" . $$resultf{ $oid_speed[$i] } . " ";
                    }
                    else {    # Bps
                        my $warn_factor = ( defined( $self->{o_meg} ) ) ? 1048576 : ( defined( $self->{o_gig} ) ) ? 1073741824 : 1024;
                        $perf_out .= "'" . $descr[$i] . "_in_Bps'=" . sprintf( "%.0f", $checkperf_out_raw[0] ) . ";";
                        $perf_out .= ( $self->{o_warn}->[0] != 0 ) ? $self->{o_warn}->[0] * $warn_factor . ";" : ";";
                        $perf_out .= ( $self->{o_crit}->[0] != 0 ) ? $self->{o_crit}->[0] * $warn_factor . ";" : ";";
                        $perf_out .= "0;" . $$resultf{ $oid_speed[$i] } . " ";
                        $perf_out .= "'" . $descr[$i] . "_out_Bps'=" . sprintf( "%.0f", $checkperf_out_raw[1] ) . ";";
                        $perf_out .= ( $self->{o_warn}->[1] != 0 ) ? $self->{o_warn}->[1] * $warn_factor . ";" : ";";
                        $perf_out .= ( $self->{o_crit}->[1] != 0 ) ? $self->{o_crit}->[1] * $warn_factor . ";" : ";";
                        $perf_out .= "0;" . $$resultf{ $oid_speed[$i] } . " ";
                    }
                }
            }
            else {    # output in octet counter
                $perf_out .= "'" . $descr[$i] . "_in_octet'=" . $$resultf{ $oid_perf_inoct[$i] } . "c ";
                $perf_out .= "'" . $descr[$i] . "_out_octet'=" . $$resultf{ $oid_perf_outoct[$i] } . "c";
            }
            if( defined( $self->{o_perfe} ) ) {
                $perf_out .= " '" . $descr[$i] . "_in_error'=" . $$resultf{ $oid_perf_inerr[$i] } . "c ";
                $perf_out .= "'" . $descr[$i] . "_in_discard'=" . $$resultf{ $oid_perf_indisc[$i] } . "c ";
                $perf_out .= "'" . $descr[$i] . "_out_error'=" . $$resultf{ $oid_perf_outerr[$i] } . "c ";
                $perf_out .= "'" . $descr[$i] . "_out_discard'=" . $$resultf{ $oid_perf_outdisc[$i] } . "c";
            }
            if( defined( $self->{o_perfs} ) ) {
                $perf_out .= " '" . $descr[$i] . "_speed_bps'=" . $$resultf{ $oid_speed[$i] };
            }
        }
    }

    # Only a few ms left...
    alarm(0);

    # Check if all interface are OK
    if( $num_ok == $num_int ) {
        if( $final_status == 0 ) {
            print $print_out, ":", $num_ok, " UP: OK";
            if( defined( $self->{o_perf} ) ) { print " | ", $perf_out; }
            print "\n";
            exit $ERRORS{"OK"};
        }
        elsif ( $final_status == 1 ) {
            print $print_out, ":(", $num_ok, " UP): WARNING";
            if( defined( $self->{o_perf} ) ) { print " | ", $perf_out; }
            print "\n";
            exit $ERRORS{"WARNING"};
        }
        elsif ( $final_status == 2 ) {
            print $print_out, ":(", $num_ok, " UP): CRITICAL";
            if( defined( $self->{o_perf} ) ) { print " | ", $perf_out; }
            print "\n";
            exit $ERRORS{"CRITICAL"};
        }
        else {
            print $print_out, ":(", $num_ok, " UP): UNKNOWN";
            if( defined($perf_out) ) { print " | ", $perf_out; }
            print "\n";
            exit $ERRORS{"UNKNOWN"};
        }
    }

    # else print the not OK interface number and exit (return is always critical if at least one int is down).

    print $print_out, ": ", $num_int - $num_ok, " int NOK : CRITICAL";
    if( defined($perf_out) ) { print " | ", $perf_out; }
    print "\n";
    exit $ERRORS{"CRITICAL"};

}

# functions

sub read_file {
    my $self = shift;

    # Input : File, items_number
    # Returns : array of value : [line][item]
    my( $traffic_file, $items_number ) = @_;
    my( $ligne, $n_rows ) = ( undef, 0 );
    my( @last_values, @file_values, $i );
    open( FILE, "<" . $traffic_file ) || return ( 1, 0, 0 );

    while ( $ligne = <FILE> ) {
        chomp($ligne);
        @file_values = split( ":", $ligne );

        #$self->verb("@file_values");
        if( $#file_values >= ( $items_number - 1 ) ) {

            # check if there is enough data, else ignore line
            for ( $i = 0; $i < $items_number; $i++ ) { $last_values[$n_rows][$i] = $file_values[$i]; }
            $n_rows++;
        }
    }
    close FILE;
    if( $n_rows != 0 ) {
        return ( 0, $n_rows, @last_values );
    }
    else {
        return ( 1, 0, 0 );
    }
}

sub write_file {
    my $self = shift;

    # Input : file , rows, items, array of value : [line][item]
    # Returns : 0 / OK, 1 / error
    my( $file_out, $rows, $item, @file_values ) = @_;
    my $start_line = ( $rows > $self->{file_history} ) ? $rows - $self->{file_history} : 0;
    if( open( FILE2, ">" . $file_out ) ) {
        for ( my $i = $start_line; $i < $rows; $i++ ) {
            for ( my $j = 0; $j < $item; $j++ ) {
                print FILE2 $file_values[$i][$j];
                if( $j != ( $item - 1 ) ) { print FILE2 ":" }
            }
            print FILE2 "\n";
        }
        close FILE2;
        return 0;
    }
    else {
        return 1;
    }
}

sub p_version {
    my $self = shift;
    print "check_snmp_int version : $self->{Version}\n";
}

sub print_usage {
    my $self = shift;
    print "Usage: $0 [-v] -H <host> -C <snmp_community> [-2] | (-l login -x passwd [-X pass -L <authp>,<privp>)  [-p <port>] -n <name in desc_oid> [-i] [-a] [-r] [-f[eSyY]] [-k[qBMGu] -g -w<warn levels> -c<crit levels> -d<delta>] [-o <octet_length>] [-t <timeout>] [-s] --label [-V]\n";
}

sub isnnum {    # Return true if arg is not a number
    my $self = shift;
    my $num  = shift;
    if( $num =~ /^(\d+\.?\d*)|(^\.\d+)$/ ) { return 0; }
    return 1;
}

sub help {
    my $self = shift;
    print "\nSNMP Network Interface Monitor for Nagios version ", $self->{Version}, "\n";
    print "GPL licence, (c)2004-2007 Patrick Proy\n\n";
    $self->print_usage();
    print <<EOT;
-v, --verbose
   print extra debugging information (including interface list on the system)
-h, --help
   print this help message
-H, --hostname=HOST
   name or IP address of host to check
-C, --community=COMMUNITY NAME
   community name for the host's SNMP agent (implies v1 protocol)
-l, --login=LOGIN ; -x, --passwd=PASSWD, -2, --v2c
   Login and auth password for snmpv3 authentication
   If no priv password exists, implies AuthNoPriv
   -2 : use snmp v2c
-X, --privpass=PASSWD
   Priv password for snmpv3 (AuthPriv protocol)
-L, --protocols=<authproto>,<privproto>
   <authproto> : Authentication protocol (md5|sha : default md5)
   <privproto> : Priv protocole (des|aes : default des)
-P, --port=PORT
   SNMP port (Default 161)
-n, --name=NAME
   Name in description OID (eth0, ppp0 ...).
   This is treated as a regexp : -n eth will match eth0,eth1,...
   Test it before, because there are known bugs (ex : trailling /)
-I, --index=Index
   Index of the interface, special for strange Windows interfaces
   Don't use with -r/--noreg, as it never uses regexp.
   See -T
-T, --test
   Prints out a List of interfaces with their appropriate indeces
-r, --noregexp
   Do not use regexp to match NAME in description OID
-i, --inverse
   Make critical when up
-a, --admin
   Use administrative status instead of operational
-o, --octetlength=INTEGER
  max-size of the SNMP message, usefull in case of Too Long responses.
  Be carefull with network filters. Range 484 - 65535, default are
  usually 1472,1452,1460 or 1440.
-f, --perfparse
   Perfparse compatible output (no output when interface is down).
-e, --error
   Add error & discard to Perfparse output
-S, --intspeed
   Include speed in performance output in bits/s
-y, --perfprct ; -Y, --perfspeed
   -y : output performance data in % of max speed
   -Y : output performance data in bits/s or Bytes/s (depending on -B)
-k, --perfcheck ; -q, --extperfcheck
   -k check the input/ouput bandwidth of the interface
   -q also check the error and discard input/output
--label
   Add label before speed in output : in=, out=, errors-out=, etc...
-g, --64bits
   Use 64 bits counters instead of the standard counters
   when checking bandwidth & performance data.
   You must use snmp v2c or v3 to get 64 bits counters.
-d, --delta=seconds
   make an average of <delta> seconds (default 300=5min)
-B, --kbits
   Make the warning and critical levels in K|M|G Bits/s instead of K|M|G Bytes/s
-G, --giga ; -M, --mega ; -u, --prct
   -G : Make the warning and critical levels in Gbps (with -B) or GBps
   -M : Make the warning and critical levels in Mbps (with -B) or MBps
   -u : Make the warning and critical levels in % of reported interface speed.
-w, --warning=input,output[,error in,error out,discard in,discard out]
   warning level for input / output bandwidth (0 for no warning)
     unit depends on B,M,G,u options
   warning for error & discard input / output in error/min (need -q)
-c, --critical=input,output[,error in,error out,discard in,discard out]
   critical level for input / output bandwidth (0 for no critical)
     unit depends on B,M,G,u options
   critical for error & discard input / output in error/min (need -q)
-s, --short=int
   Make the output shorter : only the first <n> chars of the interface(s)
   If the number is negative, then get the <n> LAST caracters.
-t, --timeout=INTEGER
   timeout for SNMP in seconds (Default: 5)
-V, --version
   prints version number
Note : when multiple interface are selected with regexp,
       all be must be up (or down with -i) to get an OK result.
EOT
}

# For verbose output
sub verb {
    my $self = shift;
    my $t    = shift;
    print $t, "\n" if defined( $self->{o_verb} );
}

sub check_options {
    my $self = shift;
    Getopt::Long::Configure("bundling");
    GetOptions(
        'v'             => \$self->{o_verb},
        'verbose'       => \$self->{o_verb},
        'h'             => \$self->{o_help},
        'help'          => \$self->{o_help},
        'H:s'           => \$self->{o_host},
        'hostname:s'    => \$self->{o_host},
        'p:i'           => \$self->{o_port},
        'port:i'        => \$self->{o_port},
        'n:s'           => \$self->{o_descr},
        'name:s'        => \$self->{o_descr},
        'I:i'           => \$self->{o_index},
        'index:i'       => \$self->{o_index},
        'T'             => \$self->{o_test},
        'test'          => \$self->{o_test},
        'C:s'           => \$self->{o_community},
        'community:s'   => \$self->{o_community},
        '2'             => \$self->{o_version2},
        'v2c'           => \$self->{o_version2},
        'l:s'           => \$self->{o_login},
        'login:s'       => \$self->{o_login},
        'x:s'           => \$self->{o_passwd},
        'passwd:s'      => \$self->{o_passwd},
        'X:s'           => \$self->{o_privpass},
        'privpass:s'    => \$self->{o_privpass},
        'L:s'           => \$self->{v3protocols},
        'protocols:s'   => \$self->{v3protocols},
        't:i'           => \$self->{o_timeout},
        'timeout:i'     => \$self->{o_timeout},
        'i'             => \$self->{o_inverse},
        'inverse'       => \$self->{o_inverse},
        'a'             => \$self->{o_admin},
        'admin'         => \$self->{o_admin},
        'r'             => \$self->{o_noreg},
        'noregexp'      => \$self->{o_noreg},
        'V'             => \$self->{o_version},
        'version'       => \$self->{o_version},
        'f'             => \$self->{o_perf},
        'perfparse'     => \$self->{o_perf},
        'e'             => \$self->{o_perfe},
        'error'         => \$self->{o_perfe},
        'k'             => \$self->{o_checkperf},
        'perfcheck'     => \$self->{o_checkperf},
        'q'             => \$self->{o_ext_checkperf},
        'extperfcheck'  => \$self->{o_ext_checkperf},
        'w:s'           => \$self->{o_warn_opt},
        'warning:s'     => \$self->{o_warn_opt},
        'c:s'           => \$self->{o_crit_opt},
        'critical:s'    => \$self->{o_crit_opt},
        'B'             => \$self->{o_kbits},
        'kbits'         => \$self->{o_kbits},
        's:i'           => \$self->{o_short},
        'short:i'       => \$self->{o_short},
        'g'             => \$self->{o_highperf},
        '64bits'        => \$self->{o_highperf},
        'S'             => \$self->{o_perfs},
        'intspeed'      => \$self->{o_perfs},
        'y'             => \$self->{o_perfp},
        'perfprct'      => \$self->{o_perfp},
        'Y'             => \$self->{o_perfr},
        'perfspeed'     => \$self->{o_perfr},
        'M'             => \$self->{o_meg},
        'mega'          => \$self->{o_meg},
        'G'             => \$self->{o_gig},
        'giga'          => \$self->{o_gig},
        'u'             => \$self->{o_prct},
        'prct'          => \$self->{o_prct},
        'o:i'           => \$self->{o_octetlength},
        'octetlength:i' => \$self->{o_octetlength},
        'label'         => \$self->{o_label},
        'd:i'           => \$self->{o_delta},
        'delta:i'       => \$self->{o_delta} );
    if( defined( $self->{o_help} ) )    { $self->help();      exit $ERRORS{"UNKNOWN"} }
    if( defined( $self->{o_version} ) ) { $self->p_version(); exit $ERRORS{"UNKNOWN"} }
    if( ( ( !defined( $self->{o_descr} ) && !defined( $self->{o_index} ) ) && !defined( $self->{o_test} ) ) || !defined( $self->{o_host} ) )    # check host and filter
    {
        $self->print_usage();
        exit $ERRORS{"UNKNOWN"};
    }
    if( defined( $self->{o_index} ) && defined( $self->{o_noreg} ) ) { print "Index is always noreg, unsetting '-r'\n"; undef $self->{o_noreg} }

    # check snmp information
    if( !defined( $self->{o_community} ) && ( !defined( $self->{o_login} ) || !defined( $self->{o_passwd} ) ) ) { print "Put snmp login info!\n"; $self->print_usage(); exit $ERRORS{"UNKNOWN"} }
    if( ( defined( $self->{o_login} ) || defined( $self->{o_passwd} ) ) && ( defined( $self->{o_community} ) || defined( $self->{o_version2} ) ) ) { print "Can't mix snmp v1,2c,3 protocols!\n"; $self->print_usage(); exit $ERRORS{"UNKNOWN"} }
    if( defined( $self->{v3protocols} ) ) {
        if( !defined( $self->{o_login} ) ) { print "Put snmp V3 login info with protocols!\n"; $self->print_usage(); exit $ERRORS{"UNKNOWN"} }
        my @v3proto = split( /,/, $self->{v3protocols} );
        if( ( defined( $v3proto[0] ) ) && ( $v3proto[0] ne "" ) ) { $self->{o_authproto} = $v3proto[0]; }    # Auth protocol
        if( defined( $v3proto[1] ) ) { $self->{o_privproto} = $v3proto[1]; }                                 # Priv  protocol
        if( ( defined( $v3proto[1] ) ) && ( !defined( $self->{o_privpass} ) ) ) {
            print "Put snmp V3 priv login info with priv protocols!\n";
            $self->print_usage();
            exit $ERRORS{"UNKNOWN"};
        }
    }
    if( defined( $self->{o_timeout} ) && ( $self->isnnum( $self->{o_timeout} ) || ( $self->{o_timeout} < 2 ) || ( $self->{o_timeout} > 60 ) ) ) { print "Timeout must be >1 and <60 !\n"; $self->print_usage(); exit $ERRORS{"UNKNOWN"} }
    if( !defined( $self->{o_timeout} ) ) { $self->{o_timeout} = 5; }

    # Check snmpv2c or v3 with 64 bit counters
    if( defined( $self->{o_highperf} ) && ( !defined( $self->{o_version2} ) && defined( $self->{o_community} ) ) ) { print "Can't get 64 bit counters with snmp version 1\n"; $self->print_usage(); exit $ERRORS{"UNKNOWN"} }
    if( defined( $self->{o_highperf} ) ) {
        if( eval "require bigint" ) {
            use bigint;
        }
        else { print "Need bigint module for 64 bit counters\n"; $self->print_usage(); exit $ERRORS{"UNKNOWN"} }
    }

    # check if -e without -f
    if( defined( $self->{o_perfe} ) && !defined( $self->{o_perf} ) ) { print "Cannot output error without -f option!\n"; $self->print_usage(); exit $ERRORS{"UNKNOWN"} }
    if( defined( $self->{o_perfr} ) && defined( $self->{o_perfp} ) ) {
        print "-Y and -y options are exclusives\n";
        $self->print_usage();
        exit $ERRORS{"UNKNOWN"};
    }
    if( ( defined( $self->{o_perfr} ) || defined( $self->{o_perfp} ) ) && !defined( $self->{o_checkperf} ) ) {
        print "Cannot put -Y or -y options without perf check option (-k) \n";
        $self->print_usage();
        exit $ERRORS{"UNKNOWN"};
    }
    if( defined( $self->{o_short} ) ) {

        #TODO maybe some basic tests ? caracters return empty string
    }
    if( defined( $self->{o_checkperf} ) ) {
        $self->{'o_warn'} = [ split( /,/, $self->{o_warn_opt} ) ];
        if( defined( $self->{o_ext_checkperf} ) && ( scalar @{ $self->{o_warn} } != 6 ) ) {
            print "6 warning levels for extended checks \n";
            $self->print_usage();
            exit $ERRORS{"UNKNOWN"};
        }
        if( !defined( $self->{o_ext_checkperf} ) && ( scalar @{ $self->{o_warn} } != 2 ) ) {
            print "2 warning levels for bandwidth checks \n";
            $self->print_usage();
            exit $ERRORS{"UNKNOWN"};
        }
        $self->{'o_crit'} = [ split( /,/, $self->{o_crit_opt} ) ];

        if( defined( $self->{o_ext_checkperf} ) && ( scalar @{ $self->{'o_crit'} } != 6 ) ) {
            print "6 critical levels for extended checks \n";
            $self->print_usage();
            exit $ERRORS{"UNKNOWN"};
        }
        if( !defined( $self->{o_ext_checkperf} ) && ( scalar @{ $self->{'o_crit'} } != 2 ) ) {
            print "2 critical levels for bandwidth checks \n";
            $self->print_usage();
            exit $ERRORS{"UNKNOWN"};
        }
        for ( my $i = 0; $i < scalar @{ $self->{o_warn} }; $i++ ) {
            if( ( $self->{o_crit}->[$i] != 0 ) && ( $self->{o_warn}->[$i] > $self->{o_crit}->[$i] ) ) {
                print "Warning must be < Critical level \n";
                $self->print_usage();
                exit $ERRORS{"UNKNOWN"};
            }
        }
        if( ( defined( $self->{o_meg} ) && defined( $self->{o_gig} ) ) || ( defined( $self->{o_meg} ) && defined( $self->{o_prct} ) ) || ( defined( $self->{o_gig} ) && defined( $self->{o_prct} ) ) ) {
            print "-M -G and -u options are exclusives\n";
            $self->print_usage();
            exit $ERRORS{"UNKNOWN"};
        }
    }
    #### octet length checks
    if( defined( $self->{o_octetlength} ) && ( $self->isnnum( $self->{o_octetlength} ) || $self->{o_octetlength} > 65535 || $self->{o_octetlength} < 484 ) ) {
        print "octet lenght must be < 65535 and > 484\n";
        $self->print_usage();
        exit $ERRORS{"UNKNOWN"};
    }
}
