#ifndef CLICK_VIDS_MULTISTEP_LW_DETECTOR_HH
#define CLICK_VIDS_MULTISTEP_LW_DETECTOR_HH
#include <click/element.hh>
#include <click/timer.hh>
#include <click/hashmap.hh>

#include <ramcloud/RamCloud.h>

using namespace RAMCloud;

CLICK_DECLS

// key uint32_t host_ip;
enum _step_t 
{
    STP_NONE,
    STP_SSH,
    STP_HTTP_DOWNLOAD,
    STP_FTP_UPLOAD
};
struct mltstp_records_t 
{
    uint32_t create_time;
    _step_t step;
};

class MLTSTP_LW_DETECTOR : public Element { 
public:
    const char *port_count() const { return "3/3"; }
    const char *class_name() const { return "MLTSTP_LW_DETECTOR"; }
    
    ~MLTSTP_LW_DETECTOR() 
    { 
        delete client; 
    }
    
    MLTSTP_LW_DETECTOR():
        _expiration_time(600),
        _ramserver(""),
        _ramname(""),
        _timer(this),
        client(NULL)
    {
    }
    int initialize(ErrorHandler*);
    int configure(Vector<String> &conf, ErrorHandler *errh);

    void run_timer(Timer*);
    void push(int port, Packet *p);

private:

    struct mltstp_records_t* is_Exist(uint32_t);

    int32_t _expiration_time;
    String _ramserver;
    String _ramname;
    Timer _timer;

    RamCloud* client;
    uint64_t tableId;

};

CLICK_ENDDECLS
#endif
