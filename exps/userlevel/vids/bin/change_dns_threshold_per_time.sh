#!/bin/bash
# test dns by changing threshold per time

set -eux

# network interface
NETINT=clan

# dir for the script
SCRIPT_DIR=$(dirname $(readlink -f $0))

# dir for click source code
CLICK_DIR=/local/work/click

# dir for click configuration for experements
CLICK_CONF=$SCRIPT_DIR/../conf/vids_userlevel.click

mkdir -p logs
LOG_FILE=logs/eval_dns_change_threshold.log

if [ $# -lt 1 ]

then
    echo -e '\033[31mUsage: '$0' [dumpfile1] [ dumpfile2] [...]\033[0m'
    exit 1
fi

DUMPFILES=$@

cd $CLICK_DIR

# ./configure LIBS="-lramcloud -L/usr/local/lib/ramcloud" --disable-linuxmodule
# make 
make -j $(getconf _NPROCESSORS_ONLN) userlevel


function change_threshld( )
{
    threshold=$1
    sed 's/DNS_THRSHLD [0-9]\+/DNS_THRSHLD '$threshold'/' $CLICK_CONF -i
}

function change_max_len()
{
    max_len=$1
    sed 's/DNS_MAX_LEN [0-9]\+/DNS_MAX_LEN '$max_len'/' $CLICK_CONF -i
}


function run_once ( )
{
    echo >> $LOG_FILE
    date '+%Y-%m-%d %H:%M:%S' >> $LOG_FILE
    echo >> $LOG_FILE
    grep '^define(' $CLICK_CONF >> $LOG_FILE

    # start click
    $CLICK_DIR/bin/click $CLICK_CONF 2>> $LOG_FILE &
    pid=$!
    sleep 3

    # replay the dump file
    for f in $DUMPFILES
    do
        # for testing the threshold, replay the packets by the original speed
        tcpreplay -i $NETINT $f
    done
    # end click
    sleep 5
    kill -2 $pid
    sleep 3
}

for len in $(seq 25 60)
do
    change_max_len $len
    run_once
done
