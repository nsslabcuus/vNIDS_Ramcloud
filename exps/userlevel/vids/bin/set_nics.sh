#!/bin/bash
# setup network namespace and network interface card for experiments
# Usage: exps/userlevel/vids/bin/set_nics.sh 2

set -eux

count=$1

function add_one_pair( )
{
    number=$1
    ip netns del click_ns_$number || true
    ovs-vsctl del-port ovs-lan click_v_$number || true

    ip link add click_v_$number type veth peer name click_v_peer_$number || true
    ip link set dev click_v_$number up
    ovs-vsctl add-port ovs-lan click_v_$number

    ip netns add click_ns_$number
    ip link set click_v_peer_$number netns click_ns_$number
    # change mac address
    ip netns exec click_ns_$number ip link set dev click_v_peer_$number address 00:00:00:00:00:0$number
    ip netns exec click_ns_$number ip addr add 172.0.0.$number/24 dev click_v_peer_$number
    ip netns exec click_ns_$number ip link set dev click_v_peer_$number up
}

ip link set dev ovs-lan up

for number in $(seq $count)
do
    add_one_pair $number
done
