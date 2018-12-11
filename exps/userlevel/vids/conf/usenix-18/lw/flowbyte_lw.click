// For userlevel experiments

define($PERFLOW_EXPIRE 300)


// Notice, I set the OUTBOUND to 1 to enable the pcap to capture the both in and out pacet. See elements/userlevel/fromdevice.cc in details.
FromDevice(click_v_1, OUTBOUND 1) -> SetTimestamp -> CheckIPHeader(14) -> PerFlowAnalysis(expire $PERFLOW_EXPIRE) -> GetRunTime -> Discard


