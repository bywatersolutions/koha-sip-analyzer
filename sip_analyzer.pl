#!/usr/bin/env perl

use Modern::Perl;

use Data::Dumper;
use Fcntl qw(:flock);
use File::Basename;
use File::Tail;
use Getopt::Long::Descriptive;
use JSON::MaybeXS qw(encode_json);
use Log::Dispatch;
use Slack::Notify;
use Term::ANSIColor;
use Time::Piece;

use constant {
    STATE_INPUT  => 1,
    STATE_OUTPUT => 2,
    MAX_DISPLAY  => 10,
};

my %pending_inputs;
my @slow_responses;
my @failed_responses;
my $prometheus;
my $last_avg    = 0;
my $last_update = time;

my $slack;
my $log;

my $average      = 0;
my $average_size = 0;

my %options;

my ( $opt, $usage ) = describe_options(
    'sip_analyzer.pl %o <logfile>',
    [ 'file|f=s',               'Log file to analyze', { required => 1 } ],
    [ 'end|e',                  'Start from the end of the file, do not process existing file data' ],
    [ 'daemon|d',               'Run as a daemon', { implies => { verbose => 0 } } ],
    [ 'prometheus|p',           'Enable Prometheus metrics' ],
    [ 'slow-threshold|s=i',     'Response time threshold in seconds',         { default => 5 } ],
    [ 'avg-slow-threshold|a=i', 'Average response time threshold in seconds', { default => 10 } ],
    [ 'slack-webhook|w=s',      'Slack webhook URL for alerts' ],
    [ 'pid-file=s',             'PID file for daemon mode', { default => 'sip_analyzer.pid' } ],
    [ 'log-file|l=s',           'Log file' ],
    [ 'verbose|v+',             'Output verbose messages' ],
    [ 'help|h',                 'Show this help message', { shortcircuit => 1, show_defaults => 1 } ],
);

# Copy options to our options hash
$options{$_} = $opt->{$_} for keys %$opt;

# Daemon mode requires a log file
if ( $options{daemon} && !$options{log_file} ) {
    die "Daemon mode requires log file\n";
}

# Set up slack if webhook was passed in
$slack = Slack::Notify->new(
    hook_url => $options{slack_webhook},
) if $options{slack_webhook};

# Set up a logger
$log = Log::Dispatch->new(
    outputs => [
        [
            'File',
            min_level => 'info',
            filename  => $options{log_file},
            mode      => 'append',
        ]
    ],
) if $options{log_file};

if ( !-r $options{file} ) {
    die "Cannot read file: $options{file}\n";
}

# Initialize Prometheus if enabled
if ( $options{prometheus} ) {
    require Net::Prometheus;
    $prometheus = Net::Prometheus->new;
    $prometheus->new_counter(
        name => 'sip_messages_total',
        help => 'Total number of SIP messages',
    );
    $prometheus->new_histogram(
        name    => 'sip_response_time_seconds',
        help    => 'Response time distribution',
        buckets => [ 0.1, 0.5, 1, 2.5, 5, 10, 30, 60 ],
    );
}

# Daemonize if requested
if ( $options{daemon} ) {
    require Daemon::Daemonize;
    Daemon::Daemonize->daemonize(
        close => 'std',
    );
}

# Set up signal handlers, we may want to do stuff and junk later
$SIG{INT} = $SIG{TERM} = sub {
    exit 0;
};

# Main processing loop
process_file( \%options );

# Process log file
sub process_file {
    my ($options) = @_;

    my $file    = $options->{file};
    my $tail    = $options->{end} ? 0 : -1;
    my $verbose = $options->{verbose};

    $file = File::Tail->new(
        name => $file,
        tail => $tail,
    );

    while ( defined( my $line = $file->read ) ) {

        # Parse the log line
        if ( $line =~ /\[(.*?)\] \[(\d+)\] \[(\w+)\] (.*?)@(.*?): (INPUT|OUTPUT) MSG: '(.*?)'/ ) {
            my ( $timestamp_str, $pid, $level, $user, $ip, $msg_type, $message ) = ( $1, $2, $3, $4, $5, $6, $7 );

            # Sometimes we get empty messages, skip them
            next unless $message;

            # Skip login messages, acs status messages
            next if $message =~ m/^(93|94|98|99)/;

            # Parse timestamp
            my $timestamp = Time::Piece->strptime( $timestamp_str, "%Y/%m/%d %H:%M:%S" );

            # Update Prometheus metrics
            if ( $options{prometheus} ) {
                $prometheus->get('sip_messages_total')->inc( { type => lc($msg_type) } );
            }

            if ( $msg_type eq 'INPUT' ) {

                # If we already have an input for this PID, move it to failed
                if ( exists $pending_inputs{$pid} ) {
                    push @failed_responses, {
                        timestamp => $pending_inputs{$pid}{timestamp},
                        pid       => $pid,
                        user      => $pending_inputs{$pid}{user},
                        ip        => $pending_inputs{$pid}{ip},
                        message   => $pending_inputs{$pid}{message},
                    };

                    say "Found input without an output: " . Data::Dumper::Dumper( $pending_inputs{$pid} )
                        if $verbose >= 2;
                    $log->info(
                        "Found input without an output: " . Data::Dumper::Dumper( $pending_inputs{$pid} ) . "\n" )
                        if $log;

                    # Keep only the last MAX_DISPLAY failed responses
                    @failed_responses = @failed_responses[ -MAX_DISPLAY .. -1 ]
                        if @failed_responses > MAX_DISPLAY;

                    # Send to Slack if configured
                    $slack->post( text => "*Input message without response*\n"
                            . "PID: $pid\n"
                            . "Time: "
                            . $pending_inputs{$pid}{timestamp}->strftime("%Y-%m-%d %H:%M:%S") . "\n"
                            . "User: "
                            . ( $pending_inputs{$pid}{user} // 'unknown' ) . "\n" . "IP: "
                            . ( $pending_inputs{$pid}{ip}   // 'unknown' ) . "\n"
                            . "Message: $pending_inputs{$pid}{message}" )
                        if $slack;
                }

                # Store the new input
                $pending_inputs{$pid} = {
                    timestamp => $timestamp,
                    user      => $user,
                    ip        => $ip,
                    message   => $message,
                };

            } elsif ( $msg_type eq 'OUTPUT' ) {
                if ( exists $pending_inputs{$pid} ) {
                    my $input         = delete $pending_inputs{$pid};
                    my $response_time = $timestamp - $input->{timestamp};
                    say "Response Time: $response_time" if $verbose;

                    # Update last average
                    $last_avg = add_to_average( $average, $average_size, $response_time );
                    $average_size++;
                    say "Average $last_avg with $average_size message pairs" if $verbose;

                    $last_update = time;

                    # Update Prometheus metrics
                    if ( $options{prometheus} ) {
                        $prometheus->get('sip_response_time_seconds')->observe($response_time);
                    }

                    # Check if response was slow
                    if ( $options{slow_threshold} && ( $response_time > $options{slow_threshold} ) ) {
                        my $slow_response = {
                            input_timestamp  => $input->{timestamp},
                            output_timestamp => $timestamp,
                            pid              => $pid,
                            user             => $input->{user},
                            ip               => $input->{ip},
                            input_message    => $input->{message},
                            output_message   => $message,
                            response_time    => $response_time,
                        };

                        say "Found slow response: " . Data::Dumper::Dumper($slow_response)                  if $verbose;
                        $log->info( "Found slow response: " . Data::Dumper::Dumper($slow_response) . "\n" ) if $log;

                        push @slow_responses, $slow_response;

                        # Keep only the last MAX_DISPLAY slow responses
                        @slow_responses = @slow_responses[ -MAX_DISPLAY .. -1 ]
                            if @slow_responses > MAX_DISPLAY;

                        # Send to Slack if configured
                        $slack->post( text => "*Slow response detected*\n"
                                . "PID: $pid\n"
                                . "Response time: ${response_time}s (threshold: $options{slow_threshold}s)\n"
                                . "User: "
                                . ( $input->{user} // 'unknown' ) . "\n" . "IP: "
                                . ( $input->{ip}   // 'unknown' ) . "\n"
                                . "Input: $input->{message}\n"
                                . "Output: $message" )
                            if $slack;
                    }

                    # Check if average is too slow
                    if ( $last_avg > $options{avg_slow_threshold} ) {
                        $slack->post( text => "*Warning: Average response time is high*\n"
                                . "Current average: ${last_avg}s\n"
                                . "Threshold: $options{avg_slow_threshold}s" )
                            if $slack;
                    }
                }
            }

            display_stats() unless $options{verbose} || $options{daemon};
        }
    }

}

# Display statistics (for interactive mode)
sub display_stats {
    my $now       = localtime;
    my $avg       = $average;
    my $avg_color = $avg > $options{avg_slow_threshold} ? 'red' : 'green';

    print "\x1b[s";       # Save cursor position
    print "\x1b[4;1H";    # Move to line 4

    print "\x1b[2K";      # Clear line
    print "Last updated: ", $now->strftime("%Y-%m-%d %H:%M:%S"), "\n";

    print "\x1b[2K";      # Clear line
    print "Average response time: ", colored( sprintf( "%.2fs", $avg ), $avg_color );
    print " of $average_size samples";
    print " (threshold: $options{avg_slow_threshold}s)", "\n\n";

    # Display slow responses
    print "\x1b[2K";      # Clear line
    print colored( "=== Last ", 'bold' ),
        colored( scalar @slow_responses,      'bold' ),
        colored( " slow responses (>",        'bold' ),
        colored( "$options{slow_threshold}s", 'bold' ),
        colored( ") ===\n",                   'bold' );

    if (@slow_responses) {
        foreach my $i ( 0 .. $#slow_responses ) {
            last if $i >= MAX_DISPLAY;
            my $resp = $slow_responses[ -$i - 1 ];
            print "\x1b[2K";    # Clear line
            printf(
                "PID: %s | Time: %s | Resp: %.2fs | User: %s | IP: %s\n",
                $resp->{pid},
                $resp->{input_timestamp}->strftime("%H:%M:%S"),
                $resp->{response_time},
                $resp->{user} // 'unknown',
                $resp->{ip}   // 'unknown',
            );
            print "\x1b[2K";    # Clear line
            print "  Input:  $resp->{input_message}\n";
            print "\x1b[2K";    # Clear line
            print "  Output: $resp->{output_message}\n\n";
        }
    } else {
        print "\x1b[2K";        # Clear line
        print "No slow responses detected.\n\n";
    }

    # Display failed responses
    print "\x1b[2K";            # Clear line
    print colored( "=== Last ", 'bold' ),
        colored( scalar @failed_responses,        'bold' ),
        colored( " inputs with no outputs ===\n", 'bold' );

    if (@failed_responses) {
        foreach my $i ( 0 .. $#failed_responses ) {
            last if $i >= MAX_DISPLAY;
            my $resp = $failed_responses[ -$i - 1 ];
            print "\x1b[2K";    # Clear line
            printf(
                "PID: %s | Time: %s | User: %s | IP: %s\n",
                $resp->{pid},
                $resp->{timestamp}->strftime("%H:%M:%S"),
                $resp->{user} // 'unknown',
                $resp->{ip}   // 'unknown',
            );
            print "\x1b[2K";    # Clear line
            print "  Message: $resp->{message}\n\n";
        }
    } else {
        print "\x1b[2K";        # Clear line
        print "No failed responses detected.\n\n";
    }

    print "\x1b[2K";            # Clear line
    print "\x1b[u";             # Restore cursor position
}

sub add_to_average {
    my ( $average, $size, $value ) = @_;
    return ( $size * $average + $value ) / ( $size + 1 );
}

# Show help message
sub show_help {
    print $usage->text;
    exit 0;
}
