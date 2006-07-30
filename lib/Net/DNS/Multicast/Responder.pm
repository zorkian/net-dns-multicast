#!/usr/bin/perl

use strict;
use IO::Socket::Multicast;
use Net::DNS;

package Net::DNS::Multicast::Server;

our $Debug = 0;       # bool; if on, _debug and _fail print messages
our %PacketCallbacks; # packetid => coderef; used for callbacks when a packet gets a response
our %PacketStates;    # packetid => state; stores the state of packets we have (easy retrieval)
our %PacketExtra;     # packetid => hashref; extra information for a packet
our %Packets;         # packetid => packet; stores ids to packet references
our %Queries;         # resource => { class => { type => [ id, id, id... ] } }; outstanding queries
our %Knows;           # resource => { class => { type => { ...info... } } }; what we know
our @QueuedAnswers;   # array of Net::DNS::RR; for using in answer packet

sub _fail {
    $@ = $_[0];
    print "Responder [$$]: $@\n" if $Debug;
    return undef;
}

sub _debug {
    return unless $Debug;
    print "Responder [$$]: $_[0]\n";
    return undef;
}

sub _pp {
    return unless $Debug;

    my $data = shift;
    my $ldata = ref $data ? $$data : $data;
    print "DEBUG: ";
    foreach (0..length($ldata)-1) {
        printf "%02x ", ord(substr($ldata, $_, 1));
    }
    print "\n";
}

# we can take arguments:
#   QueryTimeout => int; seconds a query is good for before we'll do it over
#   TimerCallback => coderef; called when we need a timer to fire later
#   Debug => bool; if on, print debugging information to STDERR
#
#
#
sub new {
    my $class = shift;
    my $self = { @_ };
    bless $self, ref $class || $class;

    # setup debugging class var
    $Debug = 1 if $self->{Debug};

    # setup the socket we're going to use
    my $sock = IO::Socket::Multicast->new(
            LocalPort => 5353,
            ReuseAddr => 1,
            Blocking  => 0,
        ) or return _fail("unable to create socket: $!");
    $sock->mcast_add("224.0.0.251")
        or return _fail("unable to subscribe to multicast group");
    $sock->mcast_dest("224.0.0.251:5353");
    $self->{sock} = $sock;

    # done, return our object
    return $self;
}

# enqueues answers to be sent out
sub _queue_answer {
    my $self = shift;
    my %answer = ( @_ );
    return undef unless $self && $answer{name} && $answer{address};

    # do some defaulting
    $answer{type} ||= 'A';
    $answer{class} ||= 'IN';
    $answer{ttl} ||= 60;

    # now push the answer RR
    my $rr = Net::DNS::RR->new( %answer )
        or return _fail("_enqueue_answer: failed creating resource record");
    _debug("_queue_answer: enqueued answer for $answer{name} $answer{class} $answer{type} $answer{address}");
    push @QueuedAnswers, $rr;

    # now return this rr
    return $rr;
}

# take some information from a %Knows information hashref and handle it.  this
# mostly just calls _queue_answer but maybe in the future this needs to be more
# sophisticated?
sub _queue_from_knows {
    my $self = shift;
    my $info = shift;
    return undef unless $self && $info;

    # basically, enqueue an answer from what we know
    _debug("_queue_from_knows: enqueue some knowledge about $info->{name}");
    $self->_queue_answer(
        map { $_ => $info->{$_} } qw(name address class type ttl),
    );
}

# someone asked for something at the same time we have a query out for that, so take a look
sub _handle_simultaneous_question {
    my $self = shift;
    my ($id, $q) = @_;
    return undef unless $self && $id && $q;

    my $pkt = $Packets{$id}
        or return _fail("_handle_simultaneous_question: id $id not found in Packets hash");
    my $extra = $self->_extra_data( $pkt );

    # if we have extra data, then it's a question we care about
    if ($extra) {
        if ($extra->{mode} eq 'claim_hostname') {
            # if it's in conflict, say so!
            # FIXME: finish implementing this, please
        }
    }

    return 1;
}

# handle a question that someone has asked
sub _process_question {
    my $self = shift;
    my $q = shift;
    return undef unless $self && $q;

    _debug("_process_question: " . $q->string);

    # now, if we have an outstanding query for this, we MAY have a probe problem
    if ($Queries{$q->qname}) {
        if (exists $Queries{$q->qname}->{$q->qclass} && exists $Queries{$q->qname}->{$q->qclass}->{$q->qtype}) {
            # so we have a query out for this too!
            foreach my $id (@{$Queries{$q->qname}->{$q->qclass}->{$q->qtype} || []}) {
                $self->_handle_simultaneous_question( $id, $q );
            }
        }
    }

    # rest of this is only if we know something about the question
    return 1 unless $Knows{$q->qname};

    # see if we know anything about a class they want
    my @classes;
    if ($q->qclass eq 'ANY') {
        push @classes, keys %{$Knows{$q->qname} || {}};
    } else {
        push @classes, $q->qclass;
    }

    # now we want to iterate over the classes to check
    foreach my $class (@classes) {
        next unless exists $Knows{$q->qname}->{$class};

        # now, see if we have the types they want
        my @types;
        if ($q->qtype eq 'ANY') {
            push @types, keys %{$Knows{$q->qname}->{$class} || {}};
        } else {
            push @types, $q->qtype;
        }

        # now iterate over types
        foreach my $type (@types) {
            next unless exists $Knows{$q->qname}->{$class}->{$type};

            # good, let's queue up an answer for this one
            $self->_queue_from_knows($Knows{$q->qname}->{$class}->{$type});
        }
    }

    return 1;
}

sub _process_answer {
    my $self = shift;
    my $rr = shift;
    return undef unless $self && $rr;

    _debug("_process_answer: " . $rr->string);
    
    # if we know something about this...
    return 1 unless $Queries{$rr->name};

    # now we want to iterate over the classes to check
    foreach my $class ($rr->class, 'ANY') {
        next unless exists $Queries{$rr->name}->{$class};

        # now iterate over types
        foreach my $type ($rr->type, 'ANY') {
            next unless exists $Queries{$rr->name}->{$class}->{$type};

            # iterate over the packet ids
            foreach my $id (@{$Queries{$rr->name}->{$class}->{$type} || []}) {
                # hit the packet callback with our $rr
                $PacketCallbacks{$id}->( $rr )
                    if $PacketCallbacks{$id};
            }
        }
    }

    return 1;
}

# send anything we have built up
sub _send_queued_answers {
    my $self = shift;
    return undef unless $self;

    # make sure we have stuff to do
    return 1 unless @QueuedAnswers;

    # another blank packet
    my $pkt = Net::DNS::Packet->new;
    $pkt->pop( "question" );

    # now push the answers
    $pkt->push( answer => @QueuedAnswers );

    # setup the header
    $pkt->header->qr(1);
    $pkt->header->aa(1);

    # send it out immediately
    $self->_send_packet( $pkt );

    @QueuedAnswers = ();
    return 1;
}

# called whenever we're readable
sub process_events {
    my $self = shift;

    # stick in a while loop to process all available events
    while (1) {
        _debug("process_events: reading datagram");

        # read some data
        my $data;
        my $addr = $self->{sock}->recv($data, 4096);
        unless ($addr) {
            _debug("process_events: no data to read");
            next if $self->{run_forever};
            return;
        }

        # dump the data
        #_pp($data);

        # now we got some, parse it if we can
        my $pkt = Net::DNS::Packet->new( \$data, 0 );
        return _debug("process_events: invalid packet read")
            unless $pkt;

        # now we have a packet, we can actually do something with the contents
        $self->_process_question($_) foreach $pkt->question;
        $self->_process_answer($_) foreach $pkt->answer;

        # now send queued answers
        $self->_send_queued_answers;
    }

    return 1;
}

sub run_server {
    # we just run the server, over and over
    my $self = shift;
    $self->{run_forever} = 1;
    $self->{sock}->blocking(1);
    $self->process_events;
    exit 0;
}

sub fd {
    my $self = shift;
    return fileno($self->{sock});
}

# call with a hostname you want to claim, or try
sub claim_hostname {
    my $self = shift;
    my ($hostname, $address, $ret) = @_;
    return undef unless $self && $hostname && $address;

    _debug("claim_hostname: attempting to claim $hostname");

    # create the packet we're going to be using (this first round, at least)
    my $pkt = $self->_create_query_packet( $hostname )
        or return _fail("claim_hostname: unable to create query packet");

    # now, per spec, we need to add in an authority section with our proposed owner
    my $rr = Net::DNS::RR->new(
        name => $hostname,
        class => 'IN',
        type => 'A',
        ttl => $self->{QueryTimeout} || 60,
        address => $address,
    );
    $pkt->push( authority => $rr );

    # now put this into our internal engine
    $self->_track_packet( $pkt, 'probing-1', sub {
        # someone is using this hostname :(
        # NOTE: we don't check for the arg ($rr) being of type 'A', because the spec
        # states that if ANY record for this name exists, and we're a newbie, we need
        # to consider it to be 'in use' and unavailable for claiming.
        $self->_drop_query( $pkt );
        $ret->( 0 );
    });

    # and now save extra data
    $self->_extra_data($pkt, {
        mode => 'claim_hostname',
        hostname => $hostname,
        address => $address,
    });

    # now send the packet with a delay and then we're done
    $self->_send_packet((rand()/4)+0.1, $pkt);

    # return the id so the user can track it later
    return $pkt->header->id;
}

# store or return a reference of some sort for a packet
sub _extra_data {
    my $self = shift;
    my ($pkt, $data) = @_;
    return undef unless $self && $pkt;

    my $id = $pkt->header->id
        or return _fail("_extra_data: no packet id available");

    if ($data) {
        return $PacketExtra{$id} = $data;
    } else {
        return $PacketExtra{$id};
    }
}

# basically kill off a packet from our system
sub _drop_query {
    my $self = shift;
    my $pkt = shift;
    return undef unless $self && $pkt;

    my $id = $pkt->header->id
        or return _fail("_drop_query: can't get id from packet");

    # for now, just mark the state as dead, and kill any callback
    $PacketStates{$id} = 'kill';
    delete $PacketCallbacks{$id};

    return 1;
}

# send out a packet again
sub _resend_packet {
    my $self = shift;
    my $old_pkt = shift;
    return undef unless $self && $old_pkt;

    # note we're sending
    _debug("_resend_packet: resending packet");

    # create blank packet
    my $pkt = Net::DNS::Packet->new;
    $pkt->pop("question"); # get rid of the blank question auto-inserted

    # copy id from old to new
    $pkt->header->id( $old_pkt->header->id );

    # add each section
    foreach my $q ($old_pkt->question) {
        $pkt->push( question => $q );
    }
    foreach my $q ($old_pkt->answer) {
        $pkt->push( answer => $q );
    }
    foreach my $q ($old_pkt->authority) {
        $pkt->push( authority => $q );
    }
    foreach my $q ($old_pkt->additional) {
        $pkt->push( additional => $q );
    }

    # now resend it
    $self->_send_packet( $pkt );

    # return the new one
    return $pkt;
}

# convert a probe into an announcement
sub _announce_probe {
    my $self = shift;
    my $pkt = shift;
    return undef unless $self && $pkt;

    # get the extra data for this probe
    my $extra = $self->_extra_data( $pkt );
    return undef unless $extra;

    # get a new blank packet
    my $new = Net::DNS::Packet->new;
    $new->pop( "question" );

    # now handle
    if ($extra->{mode} eq 'claim_hostname') {
        $Knows{$extra->{hostname}}->{'IN'}->{'A'} = {
            name => $extra->{hostname},
            class => 'CLASS32769', # type "IN" + msb set
            type => 'A',
            address => $extra->{address},
            ttl => $self->{QueryTimeout} || 60,
        };
        $self->_queue_from_knows( $Knows{$extra->{hostname}}->{'IN'}->{'A'} );
        $self->_schedule(1, sub {
            $self->_queue_from_knows( $Knows{$extra->{hostname}}->{'IN'}->{'A'} );
            $self->_update_tracking;
        });
    }

    return 1;
}

# iterate over packets we're tracking and handle them
sub _update_tracking {
    my $self = shift;
    return undef unless $self;

    return if $self->{is_tracking};
    $self->{is_tracking} = 1;

    _debug("_update_tracking: triggered");

    # iterate over each id we're tracking
    foreach my $id (keys %PacketStates) {
        my $state = $PacketStates{$id};
        my $packet = $Packets{$id};

        my ($next, $done) = ($state, 0);

        if ($state eq 'probing-1') {
            $next = 'probing-2';
            $self->_resend_packet( $packet );

        } elsif ($state eq 'probing-2') {
            $next = 'probing-3';
            $self->_resend_packet( $packet );

        } elsif ($state eq 'probing-3') {
            $self->_announce_probe( $packet );
            $done = 1;

        } elsif ($state eq 'announce-1') {
            $next = 'announce-2';
            $self->_resend_packet( $packet );

        } elsif ($state eq 'announce-2') {
            $done = 1;

        } elsif ($state eq 'kill') {
            $done = 1;

        } else {
            _fail("_update_tracking: invalid/unknown state $state");
            $done = 1;

        }

        # now update the packet
        $PacketStates{$id} = $next;

        # if we're done tracking this packet, sweet
        if ($done) {
            delete $PacketStates{$id};
            delete $Packets{$id};

            # nuke anything in %Queries that references this id
            foreach my $q ($packet->question) {
                if (exists $Queries{$q->qname} && exists $Queries{$q->qname}->{$q->qclass}
                        && exists $Queries{$q->qname}->{$q->qclass}->{$q->qtype})
                {
                    @{$Queries{$q->qname}->{$q->qclass}->{$q->qtype}} =
                        grep { $_ != $id } @{$Queries{$q->qname}->{$q->qclass}->{$q->qtype} || []};
                }
            }
            
        }

        # and dump debugging if desired
        _debug("_update_tracking: $id tracked; $state to $next; done=$done");
    }

    # we may have some queued data to send
    $self->_send_queued_answers;

    # enqueue another call to us
    if (%PacketStates) {
        _debug("_update_tracking: scheduling another call");
        $self->_schedule(1, sub { $self->_update_tracking; });
    }

    # reenable tracking
    $self->{is_tracking} = 0;
}

# inserts a packet into our tracking system so we know what's going on with it
sub _track_packet {
    my $self = shift;
    my ($pkt, $state, $ret) = @_;
    return undef unless $self && $pkt;

    # default
    $state ||= 'query';

    # get id to use
    my $id = $pkt->header->id
        or return _fail("_track_packet: no id from packet");

    # now register this packet in our tracking system
    $Packets{$id} = $pkt;
    $PacketStates{$id} = $state;
    $PacketCallbacks{$id} = $ret;

    # now register it at the level of each individual question
    foreach my $q ($pkt->question) {
        push @{$Queries{$q->qname}->{$q->qclass}->{$q->qtype} ||= []}, $id;
    }

    # queue up something to hit us back in half a second
    $self->_schedule(0.5, sub { $self->_update_tracking; })
        unless $self->{is_tracking};

    # return the packet, in case someone's using it?
    return $pkt;
}

# sends a packet out into the void with an optional delay
sub _send_packet {
    my $self = shift;
    return undef unless $self && @_;

    # standard args, packet is required
    my ($delay, $pkt) = @_;
    return undef unless defined $delay;

    # see if we have a time delay
    if (! ref $delay) {
        $delay += 0;
        _debug("_send_packet: delaying send by $delay seconds");

        # only do this if they gave us a non-negative/non-zero delay
        if ($delay > 0) {
            $self->_schedule($delay, sub {
                $self->_send_packet($pkt);
            });
            return 1;
        }
    }

    # if we get here, we had no delay, so shift the arg
    $pkt = $delay;

    # ARGH
    my $id = $pkt->header->id;
    $pkt->header->id(0);

    # dump this packet to the line! yay
    my $bytes = $self->{sock}->mcast_send( $pkt->data )
        or return _fail("_send_packet: unable to send packet");
    _debug("_send_packet: wrote $bytes bytes to multicast group");

    # ARGH 2
    $pkt->header->id($id);

    # done sending out the packet
    return 1;
}

# create a packet containing some number of queries for sending
sub _create_query_packet {
    my $self = shift;
    return undef unless $self && @_;

    # variables used inside that have to be in this scope
    my $pkt;

    # iterate over our parameters
    foreach my $q (@_) {
        next unless $q;

        # load, but use arrayrefs as data sets
        my ($name, $type, $class);
        ($name, $type, $class) = @$q
            if ref $q && ref $q eq 'ARRAY';

        # default to resources on the internet zone
        $name ||= $q;
        $type ||= "ANY";
        $class ||= "ANY";

        # if we don't have a packet, create it
        if (! $pkt) {
            $pkt = Net::DNS::Packet->new( $name, $type, $class )
                or return _fail("_create_query_packet: failure creating packet");

        } else {
            # but since we do, create a question and append it
            my $qobj = Net::DNS::Question->new( $name, $type, $class )
                or return _fail("_create_query_packet: failure creating question");
            $pkt->push( question => $qobj );
        }
    }

    # done, return our packet
    return $pkt;
}

# just schedules an event to happen in the future
sub _schedule {
    my $self = shift;
    my ($delay, $subref) = @_;
    return undef unless $delay && $subref;

    _debug("_schedule: event in $delay seconds, give or take");

    if ($self->{TimerCallback}) {
        # they provided a callback that gives us at least 1 second granularity, but
        # maybe something more... it doesn't have to be totally accurate
        return $self->{TimerCallback}->($delay, $subref);

    } else {
        # if they don't have a timer request callback, then we do it ourselves by
        # sleeping for the delay requested, and then call the subref.  we also warn
        # about it once...
        unless ($self->{_warned_timer_cb}) {
            warn "WARNING: You do not have a TimerCallback defined, so we're using stupid mode.\n";
            $self->{_warned_timer_cb} = 1;
        }
        select undef, undef, undef, $delay;
        $subref->();
    }
}

1;
