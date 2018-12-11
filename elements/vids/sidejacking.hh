#ifndef CLICK_SIDEJACKING_HH
#define CLICK_SIDEJACKING_HH
#include <click/element.hh>
#include <click/ipaddress.hh>

#include <ramcloud/RamCloud.h>

using namespace RAMCloud;

CLICK_DECLS

// key char* cookie;

typedef struct sidejacking_record
{
    uint32_t ip;
    char* user_agent;
}sidejacking_record; 

#define DHCP_CONTEXT_AVALIABLE 0

class SIDEJACKING : public Element {

private:
    int _anno;

    String _ramserver;
    String _ramname;

    uint64_t tableId;
    RamCloud* client;

public:

    SIDEJACKING() CLICK_COLD;
    ~SIDEJACKING() CLICK_COLD;

    const char *class_name() const		{ return "SIDEJACKING"; }
    const char *port_count() const		{ return PORTS_1_1; }

    bool can_live_reconfigure() const		{ return true; }
    int configure(Vector<String> &conf, ErrorHandler *errh);

    int initialize(ErrorHandler *errh);
    sidejacking_record* is_Exist(char*);
    bool add_record(char*, sidejacking_record* record);
    virtual void push(int port, Packet* p);
};

CLICK_ENDDECLS
#endif
