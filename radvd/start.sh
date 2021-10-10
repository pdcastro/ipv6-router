#!/bin/bash

ROUTER_INTERFACE='eth0'
ROUTED_PREFIX='2001:470:1f1d:1dc::/64'
TUNNEL_PREFIX='2001:470:1f1c:1dd::/64'
TUNNEL_REMOTE_GW="${TUNNEL_PREFIX/::\/*/::1}"
TUNNEL_LOCAL_IP6="${TUNNEL_PREFIX/::\//::2\/}"
TUNNEL_REMOTE_IP4='216.66.88.98'
TUNNEL_LOCAL_IP4='192.168.1.86'

function setup_6in4_tunnel {
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		nmcli connection add \
			con-name he-sit ifname he-sit \
			type ip-tunnel mode sit \
			remote "${TUNNEL_REMOTE_IP4}" local "${TUNNEL_LOCAL_IP4}" -- \
			ipv4.method disabled ipv6.method manual \
			ipv6.gateway "${TUNNEL_REMOTE_GW}" \
			ipv6.address "${TUNNEL_LOCAL_IP6}"
}

function del_6in4_tunnel {
	DBUS_SYSTEM_BUS_ADDRESS=unix:path=/host/run/dbus/system_bus_socket \
		nmcli connection del he-sit
}

function setup_routing {
	ip -6 addr add "${ROUTED_PREFIX/::\//::1\/}" dev ${ROUTER_INTERFACE}
	sysctl net.ipv6.conf.all.forwarding=1
}

function setup_firewall {
	ip6tables -N IPV6-ROUTER-FWD
	ip6tables -F IPV6-ROUTER-FWD
	ip6tables -A IPV6-ROUTER-FWD -s "${ROUTED_PREFIX}" -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -d "${ROUTED_PREFIX}" -j ACCEPT
	ip6tables -A IPV6-ROUTER-FWD -j REJECT --reject-with icmp6-adm-prohibited

	ip6tables -N IPV6-ROUTER-IN
	ip6tables -F IPV6-ROUTER-IN
	# Do we need to accept ICMPv6 from the whole world? All types? Security?
	ip6tables -A IPV6-ROUTER-IN -s fe80::/64 -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -s "${TUNNEL_PREFIX}" -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -s "${ROUTED_PREFIX}" -p ipv6-icmp -j ACCEPT
	ip6tables -A IPV6-ROUTER-IN -j REJECT --reject-with icmp6-adm-prohibited

	ip6tables -D INPUT   -j IPV6-ROUTER-IN
	ip6tables -A INPUT   -j IPV6-ROUTER-IN
	ip6tables -D FORWARD -j IPV6-ROUTER-FWD
	ip6tables -A FORWARD -j IPV6-ROUTER-FWD
}

function start_radvd {
	local PID_FILE='/run/radvd.pid'
	while true; do
		rm -f "$PID_FILE"
		radvd -p "$PID_FILE" -m logfile -l '/data/radvd.log'
		sleep 5
		local RADVD_PID=$(cat "$PID_FILE")
		while kill -s 0 "$RADVD_PID" &>/dev/null; do
			sleep 30
		done
	done
}

function main {
	del_6in4_tunnel
	setup_6in4_tunnel
	setup_routing
	setup_firewall
	start_radvd
}

main
