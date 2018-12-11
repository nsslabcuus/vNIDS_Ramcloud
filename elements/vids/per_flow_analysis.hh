#ifndef CLICK_VIDS_PERFLOWANALYSIS_HH
#define CLICK_VIDS_PERFLOWANALYSIS_HH

#include <ramcloud/RamCloud.h>
#include <click/timer.hh>
#include <click/element.hh>
#include <set>

using namespace RAMCloud;

CLICK_DECLS

typedef struct perflow_key
{
    uint32_t src_ip;
    uint32_t dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

} perflow_key;
typedef struct perflow_value
{
    uint32_t last_time;
    uint32_t create_time;

    uint32_t packetcounter;
    uint32_t packetsizecounter;

} perflow_value;

class PerFlowAnalysis : public Element {

public:
    PerFlowAnalysis();
    ~PerFlowAnalysis();

    const char* class_name() const { return "PerFlowAnalysis"; }
    const char* port_count() const { return PORTS_1_1; }
    
    int initialize(ErrorHandler*);
    int configure(Vector<String> &conf, ErrorHandler *errh);

    void run_timer(Timer*);
    virtual void push(int, Packet*);
private:
    struct perflow_value* is_Exist(struct perflow_key* pkey); 
    bool add_record(struct perflow_key* pkey, struct perflow_value* pvalue);
    void delete_timeout_record();
    int cnt;    
    int32_t _expiration_time;

    String _ramserver;
    String _ramname;
    Timer _timer;
    
    uint64_t tableId;
    RamCloud* client;
};

CLICK_ENDDECLS
#endif
