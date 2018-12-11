#ifndef CLICK_MLTSTP_HW_DETECTOR_HH
#define CLICK_MLTSTP_HW_DETECTOR_HH
#include <click/element.hh>
#include <click/ipaddress.hh>

#include <ramcloud/RamCloud.h>
using namespace RAMCloud;


CLICK_DECLS

// key uint32_t ip;
typedef struct mltstp_hw_records
{
    uint32_t steps;
    uint32_t create_time;
}mltstp_hw_records; 

#define MLTSTP_HW_EXPIRATION 3600

class MLTSTP_HW_DETECTOR : public Element {

private:
    int _anno;
    String _ramserver;
    String _ramname;

    RamCloud* client;
    uint64_t tableId;

public:

    MLTSTP_HW_DETECTOR() CLICK_COLD;
    ~MLTSTP_HW_DETECTOR() CLICK_COLD;

    const char *class_name() const		{ return "MLTSTP_HW_DETECTOR"; }
    const char *port_count() const		{ return PORTS_1_1; }

    bool can_live_reconfigure() const		{ return true; }

    int configure(Vector<String> &conf, ErrorHandler *errh);

    int initialize(ErrorHandler *errh);
    mltstp_hw_records* is_Exist(uint32_t);
    void add_record(uint32_t, mltstp_hw_records*);
    void delete_record(uint32_t);
    //Packet *pull(int);
    Packet *simple_action(Packet *p);

};

CLICK_ENDDECLS
#endif
