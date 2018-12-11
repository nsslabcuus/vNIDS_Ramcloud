#ifndef CLICK_DNSTUNNELS_HH
#define CLICK_DNSTUNNELS_HH

#include <click/timer.hh>
#include <click/element.hh>
#include <click/ipaddress.hh>

#include <ramcloud/RamCloud.h>
using namespace RAMCloud;


CLICK_DECLS

// key uint32_t host_ip;

typedef struct dnstunnels_record
{
    int count;
    uint32_t create_time;
}dnstunnels_record; 

#define DNSTUNNELS_EXPIRATION 100
#define COUNT_THRESHOLD 100
#define PERCENTAGE_OF_COUNT 2
#define DNSTUNNELS_QUERY_LEN_THRESHOLD 27
#define REQUEST_COUNT_THRESHOLD 100

class DNSTUNNELS : public Element {
private:
    int _anno;
    uint64_t tableId;
    RamCloud* client;

public:

    DNSTUNNELS() CLICK_COLD;
    ~DNSTUNNELS() CLICK_COLD;

    const char *class_name() const		{ return "DNSTUNNELS"; }
    const char *port_count() const		{ return PORTS_1_1; }

    bool can_live_reconfigure() const		{ return true; }

    int configure(Vector<String> &conf, ErrorHandler *errh);
    dnstunnels_record* is_Exist(uint32_t host_ip);
    bool add_record(uint32_t, uint32_t);
    bool delete_record(uint32_t);
    Packet *pull(int port);

};

CLICK_ENDDECLS
#endif
