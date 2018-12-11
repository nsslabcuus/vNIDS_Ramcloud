#!/usr/bin/gawk -f
#
# test for dns lw hw processing time
#
# Usage: exps/userlevel/vids/bin/dns_time.awk logs/eval_dns_change_threshold.log
#

match($0, /\$DNS_MAX_LEN ([0-9]+)\)$/, m) {
    if(max_len)
    {
        print max_len","tagged","untagged","
    }
    max_len = m[1]
}
$3 == "PTAG_DNS_TUNNEL" {
    gsub(/[\r\n]/, "", $6)
    tagged = $6
    }
$3 == "NONE_PTAG_DNS_TUNNEL" {
    gsub(/[\r\n]/, "", $6)
    untagged = $6
    }
END {
    if(max_len)
    {
        print max_len","tagged","untagged","
    }
}

