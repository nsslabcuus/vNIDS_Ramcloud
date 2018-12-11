define($DNS_MAX_LEN 30)
define($DNS_EXPIRE  60)
define($DNS_THRSHLD 5)

define($src_mac 90:e2:ba:ac:18:bc)
define($dst_mac 90:e2:ba:b3:20:e0)
define($IN_device ovs-lan)

define($RAMSERVER "tcp:host=10.10.1.4,port=11100")
define($RAMNAME "__unnamed__")

// Definition of VNF_OUT. set MAC here. 
VNF_OUT :: {
    input[0]->StoreEtherAddress($src_mac,src)-> StoreEtherAddress($dst_mac,dst) -> [0]output;
};

VNF_OUT[0] -> Print(MAXLENGTH -1) -> ToDevice($IN_device);


tudp :: IPClassifier (
    udp,
    -)

IPclasses :: Classifier(
 12/0800,
 -)


FromDevice($IN_device, OUTBOUND 1)  ->  IPclasses
IPclasses[0] -> CheckIPHeader(14) -> IPReassembler() -> GeneveEncap(opt_len 4) -> tudp
IPclasses[1] -> Discard
tudp[1] -> Discard

tudp[0] -> DNS_LW_DETECTOR(expire $DNS_EXPIRE, threshold $DNS_THRSHLD, max_len $DNS_MAX_LEN, ramserver $RAMSERVER, ramname $RAMNAME) -> SetIPChecksum ->

SimpleQueue() -> [0] VNF_OUT; 
