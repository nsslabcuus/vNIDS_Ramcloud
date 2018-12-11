#include <click/config.h>
#include <click/args.hh>
#include <click/logger.h>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>

#include <ramcloud/TableEnumerator.h>
#include <ramcloud/ClientException.h>

#include "mltstp_lw_detector.hh"
#include "packet_tags.hh"

CLICK_DECLS

int 
MLTSTP_LW_DETECTOR::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

int 
MLTSTP_LW_DETECTOR::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int ret =  Args(conf, this, errh).read("expire", _expiration_time)
               .read("ramserver", _ramserver)
               .read("ramname", _ramname)
               .execute();
   
    if (_ramserver.empty() || _ramname.empty()) {
        LOGE("Init failed due to ramcloud server or name are not configured! %s %s", _ramserver.c_str(), _ramname.c_str());
        return -EINVAL;
    }
 
    client = new RamCloud(_ramserver.c_str(), _ramname.c_str());
    try
    {
        client->dropTable("MLTSTP_LW_DETECTOR");
    }
    catch(...)
    {
        LOG("Table MLTSTP_LW_DETECTOR Does not Exist!");
    }
    // create table
    tableId = client->createTable("MLTSTP_LW_DETECTOR", 2);   

    return ret;
}

void
MLTSTP_LW_DETECTOR::run_timer(Timer* timer)
{
    assert(timer == &_timer);
    TableEnumerator iter(*client, tableId, false);
    uint32_t expire_at = Timestamp::now().sec() - _expiration_time;
  
    const void* buffer;
    uint32_t size = 0;

    while(iter.hasNext())
    {
        iter.next(&size, &buffer);

        Object object(buffer, size);

        uint32_t key = *((uint32_t*)object.getKey());
        struct mltstp_records_t* value = (struct mltstp_records_t*)object.getValue();
        
        if (value->create_time < expire_at)
        {
            client->remove(tableId, &key, sizeof(key)); 
        }
        LOG_DEBUG("MLTSTP_LW_DETECTOR::RAMCloud: remove key: src %x\n", key);
    
    }
}

struct mltstp_records_t*
MLTSTP_LW_DETECTOR::is_Exist(uint32_t src_ip) 
{
    Buffer buffer;
    try
    {
        client->read(tableId, &src_ip, sizeof(src_ip), &buffer); 
    }
    catch(...)
    {
        LOG_DEBUG("MLTSTP_LW_DETECTOR RAMCloud Exception: Host not exist %x\n",src_ip);
        return NULL;
    }
    return static_cast<struct mltstp_records_t*>(buffer.getRange(0, buffer.size()));
}

void 
MLTSTP_LW_DETECTOR::push(int port, Packet *p)
{
    uint32_t host_ip = 0;
    const click_ip *ip_header = p->ip_header();
    const click_tcp *tcp_header = p->tcp_header();
    _step_t possible_step;

    switch(port)
    {
        case 0:     // http download, extract the ip_dst
            if(ntohs(tcp_header->th_sport) != 80)
                return output(port).push(p);
            host_ip = ip_header->ip_dst.s_addr;
            possible_step = STP_HTTP_DOWNLOAD;
            break;
        case 1:     // ftp upload, extract the ip_src
            if(ntohs(tcp_header->th_dport) != 20)
                return output(port).push(p);
            host_ip = ip_header->ip_src.s_addr;
            possible_step = STP_FTP_UPLOAD;
            break;
        case 2:     // ssh login, extract the ip_src. Since we think a ssh-key-exchange msg from server indicates a ssh login attempt
            if(ntohs(tcp_header->th_sport) != 22)
                return output(port).push(p);
            host_ip = ip_header->ip_src.s_addr;
            possible_step = STP_SSH;
            break;
        default:
            LOG_ERROR("port imposssible");
            p->kill();
            return;
    }

    struct mltstp_records_t *record = is_Exist(host_ip);
    int fl = 0;
    if(NULL == record)
    {
        if(STP_SSH == possible_step)
        {
            record = (mltstp_records_t*)malloc(sizeof(mltstp_records_t));
            record->create_time = Timestamp::now().sec();
            record->step = STP_NONE;
            fl = 1;
        }
        else // if first packet is not ssh login, do not set PTAG_MLTSTP
            // output port is the same as the input port
            return output(port).push(p);
    }

    if(possible_step <= record->step + 1)
    {
        set_tag(p, PTAG_MLTSTP);
        if(possible_step == record->step + 1)
        {
            record->step = possible_step;
        }
    }
    
    try
    {
        client->write(tableId, &host_ip, sizeof(uint32_t), record, sizeof(struct mltstp_records_t));
    }
    catch(...)
    {
        LOG_DEBUG("MLTSTP_LW_DETECTOR RamCloudException: Add record failed: src %x\n", host_ip);
    }

    LOG_DEBUG("MLTSTP_LW_DETECTOR RAMCloud Add record sucessfully: src %x\n", host_ip);
    
    if (fl)
    {
        free(record);
    }
    output(port).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MLTSTP_LW_DETECTOR)
