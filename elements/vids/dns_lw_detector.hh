#ifndef CLICK_VIDS_DNS_LW_DETECTOR_HH
#define CLICK_VIDS_DNS_LW_DETECTOR_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <ramcloud/RamCloud.h>

using namespace RAMCloud;

CLICK_DECLS

// key uint32_t sip

struct dns_record_t
{
        uint32_t create_time;
        uint32_t count;
};

class DNS_LW_DETECTOR : public Element { 
public:
    
    const char *port_count() const { return PORTS_1_1; }
    const char *class_name() const { return "DNS_LW_DETECTOR"; }

    DNS_LW_DETECTOR();
    ~DNS_LW_DETECTOR();

    int initialize(ErrorHandler*);
    int configure(Vector<String> &conf, ErrorHandler *errh);

    /** @brief update record
     * @return true if need dpi
     */
    bool update_record(uint32_t, struct dns_record_t*);
    void del_timeout_records();
    bool add_record(uint32_t, struct dns_record_t*);
    struct dns_record_t* is_Exist(uint32_t src_ip); 
    void run_timer(Timer*);
    void push(int port, Packet *p);
private:
    uint32_t _expiration_time;
    uint32_t _count_threshold;
    uint32_t _payload_len_threshold;
    String _ramserver;
    String _ramname;
    Timer _timer;
    
    uint64_t tableId;
    RamCloud* client;
};

CLICK_ENDDECLS

#endif
