##! Local site policy. Customize as appropriate.
##!
##! This file will not be overwritten when upgrading or reinstalling!

# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
redef digest_salt = "blacktop";

redef Site::local_nets += { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 };


# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Estimate and log capture loss.
@load misc/capture-loss

# Enable logging of memory, packet and lag statistics.
@load misc/stats

# Load the scan detection script.  It's disabled by default because
# it often causes performance issues.
@load misc/scan

# Detect traceroute being run on the network. This could possibly cause
# performance trouble when there are a lot of traceroutes on your network.
# Enable cautiously.
#@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more
# information.
@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
@load protocols/ftp/software
@load protocols/smtp/software
@load protocols/ssh/software
@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when
# running on live traffic.  Enable it cautiously.
@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets
# where the name is not part of your local DNS zone and is being hosted
# externally.  Requires that the Site::local_zones variable is defined.
@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
@load protocols/ftp/detect

# Scripts that do asset tracking.
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
@load protocols/ssl/validate-certs

# This script prevents the logging of SSL CA certificates in x509.log
@load protocols/ssl/log-hostcerts-only

# If you have GeoIP support built in, do some geographic detections and
# logging for SSH traffic.
@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
@load protocols/http/detect-sqli

#### Network File Handling ####

# Enable MD5 and SHA1 hashing for all files.
@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
@load frameworks/files/detect-MHR

# Extend email alerting to include hostnames
@load policy/frameworks/notice/extend-email/hostnames

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
@load policy/protocols/ssl/heartbleed

# Uncomment the following line to enable logging of connection VLANs. Enabling
# this adds two VLAN fields to the conn.log file.
@load policy/protocols/conn/vlan-logging

# Uncomment the following line to enable logging of link-layer addresses. Enabling
# this adds the link-layer address for each connection endpoint to the conn.log file.
@load policy/protocols/conn/mac-logging

# Custom conn geoip enrichment
@load geodata/conn-add-geodata.zeek
# Log all plain-text http/ftp passwords
@load passwords/log-passwords.zeek

@load file-extraction

# JSON Plugin
@load json-streaming-logs
#redef JSONStreaming::disable_default_logs=T;
redef LogAscii::use_json=T;

@load policy/tuning/json-logs.zeek

@load base/frameworks/broker


# Enable peers to connect via Broker and subscribe to Zeek-internal
# communication, e.g., to register as logger node.
event zeek_init()
  {
  Broker::listen(Broker::default_listen_address, Broker::default_port,
                 Broker::default_listen_retry);
  }

  ##! Add countries for the originator and responder of a connection
##! to the connection logs.

module Conn;

export {
	redef record Conn::Info += {
		## Country code for the originator of the connection based
		## on a GeoIP lookup.
		orig_cc: string &optional &log;
		## Country code for the responser of the connection based
		## on a GeoIP lookup.
		resp_cc: string &optional &log;
		## City for the originator of the connection based
		## on a GeoIP lookup.
		orig_city: string &optional &log;
		## Cityfor the responser of the connection based
		## on a GeoIP lookup.
		resp_city: string &optional &log;
		## City for the originator of the connection based
		## on a GeoIP lookup.
		orig_region: string &optional &log;
		## Cityfor the responser of the connection based
		## on a GeoIP lookup.
		resp_region: string &optional &log;
		## latitude for the originator of the connection based
		## on a GeoIP lookup.
		orig_lat: double &optional &log;
		## longitude for the originator of the connection based
		## on a GeoIP lookup.
		orig_long: double &optional &log;
		## latitudefor the responser of the connection based
		## on a GeoIP lookup.
		resp_lat: double &optional &log;
		## longitude for the responser of the connection based
		## on a GeoIP lookup.
		resp_long: double &optional &log;
	};
}

event connection_state_remove(c: connection)
	{
	local orig_loc = lookup_location(c$id$orig_h);
	if ( orig_loc?$country_code )
		c$conn$orig_cc = orig_loc$country_code;
	if ( orig_loc?$region )
		c$conn$orig_region = orig_loc$region;    
	if ( orig_loc?$city )
		c$conn$orig_city = orig_loc$city;
	if ( orig_loc?$latitude )
		c$conn$orig_lat = orig_loc$latitude;
	if ( orig_loc?$longitude )
		c$conn$orig_long = orig_loc$longitude;

	local resp_loc = lookup_location(c$id$resp_h);
	if ( resp_loc?$country_code )
		c$conn$resp_cc = resp_loc$country_code;
	if ( resp_loc?$region )
		c$conn$resp_region = resp_loc$region;
	if ( resp_loc?$city )
		c$conn$resp_city = resp_loc$city;
	if ( resp_loc?$latitude )
		c$conn$resp_lat = resp_loc$latitude;
	if ( resp_loc?$longitude )
		c$conn$resp_long = resp_loc$longitude;
	}