#ifndef CLICK_VIDS_PORTSCAN_HH
#define CLICK_VIDS_PORTSCAN_HH

#include <ramcloud/RamCloud.h>
#include <click/timer.hh>
#include <click/element.hh>

using namespace RAMCloud;

#define MAX_HOST 25
#define MAX_PORT 15

CLICK_DECLS

// key uint32_t src_ip;

// value
struct portscan_record
{
    uint16_t portsize;
    uint16_t hostsize;

    uint32_t last_time;
    uint32_t create_time;

    uint64_t hosts[MAX_HOST];
    uint16_t ports[MAX_PORT];

    uint32_t packetcounter;
    uint32_t packetsizecounter;

};

class PortScan : public Element {

public:
    PortScan();
    ~PortScan();

    const char* class_name() const { return "PortScan"; }
    const char* port_count() const { return PORTS_1_1; }
    
    int initialize(ErrorHandler*);
    int configure(Vector<String> &conf, ErrorHandler *errh);

    void run_timer(Timer*);
    virtual void push(int, Packet*);
private:
    struct portscan_record* is_Exist(uint64_t); 
    void update_record(uint64_t, struct portscan_record*);
    bool add_record(uint64_t, struct portscan_record*);
    void delete_timeout_record();

    int32_t _expiration_time;
    String _ramserver;
    String _ramname;

    Timer _timer;

    uint64_t tableId;
    RamCloud* client;

};

CLICK_ENDDECLS
#endif
