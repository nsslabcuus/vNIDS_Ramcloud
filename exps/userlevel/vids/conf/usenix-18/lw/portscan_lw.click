// lightweight part

define($PORTSCAN_EXPIRE  60)
define($FROM_DEV click_v_1)
define($TO_DEV click_v_1)

mac_filter::Classifier(
12/0800, 
-);

// Add a classifier to filter out the IP packets 
FromDevice($FROM_DEV) ->mac_filter[0] ->
//Classifier(0/000000000001)[0] -> 
SetTimestamp -> CheckIPHeader(14) -> IPReassembler() -> GeneveEncap(opt_len 4)
-> PortScan(expire $PORTSCAN_EXPIRE) -> GetRunTime -> Discard

mac_filter[1] -> Discard
