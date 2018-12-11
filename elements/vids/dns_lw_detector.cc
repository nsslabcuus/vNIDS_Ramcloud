#include <click/config.h>
#include <click/args.hh>
#include <clicknet/udp.h>
#include <click/logger.h>

#include <stdio.h>
#include <time.h>
#include <ramcloud/TableEnumerator.h>
#include <ramcloud/ClientException.h>

#include "dns_lw_detector.hh"
#include "packet_tags.hh"

CLICK_DECLS


double time_diff(struct timeval x , struct timeval y)
{
    double x_ms , y_ms , diff;
    x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
    y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
    diff = (double)y_ms - (double)x_ms;                     
    return diff;
}



DNS_LW_DETECTOR::DNS_LW_DETECTOR(): _expiration_time(10), _count_threshold(10),
        _payload_len_threshold(100), _ramserver(""), _ramname(""),
        _timer(this), client(NULL)
{
}

int DNS_LW_DETECTOR::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int ret =  Args(conf, this, errh).read("expire", _expiration_time)
        .read("threshold", _count_threshold)
        .read("max_len", _payload_len_threshold)
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
        // client->dropTable("DNS_LW_DETECOR");
        tableId = client->getTableId("DNS_LW_DETECOR");
    }
    catch(...)
    {
        LOG_DEBUG("Table DNS_LW_DETECTOR does not exist! Create New one!"); 
        // create table
        tableId = client->createTable("DNS_LW_DETECOR", 2);
    }

    return ret;
}

int DNS_LW_DETECTOR::initialize(ErrorHandler *)
{
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}


struct dns_record_t* 
DNS_LW_DETECTOR::is_Exist(uint32_t src_ip)
{
    Buffer buffer;
    try
    {
        client->read(tableId, &src_ip, sizeof(src_ip), &buffer); 
    }
    catch(...)
    {
        LOG_DEBUG("DNS_LW_DETECTOR RAMCloud Exception: Host not exist %x\n",src_ip);
        return NULL;
    }
    return static_cast<struct dns_record_t*>(buffer.getRange(0, buffer.size()));
}

bool
DNS_LW_DETECTOR::add_record(uint32_t src_ip, struct dns_record_t* value)
{
    try
    {
        client->write(tableId, &src_ip, sizeof(uint32_t), value , sizeof(struct dns_record_t));
    }
    catch(...)
    {
        LOG_DEBUG("DNS_LW_DETECTOR RamCloudException: Add record failed: src %x\n", src_ip);
        return false;
    }
    LOG_DEBUG("DNS_LW_DETECTOR RAMCloud Add record sucessfully: src %x\n", src_ip);
     
    return true;
}

bool DNS_LW_DETECTOR::update_record(uint32_t src_ip, struct dns_record_t* value)
{
    Buffer buffer;
    try
    {
        // LOG("Counts %d\n", value->count);
        if (value->count > _count_threshold)
        {
            LOG_EVAL("Suspicious DNS! ip %d query num %d > %d in %ds",src_ip, value->count, _count_threshold, _expiration_time);

            client->remove(tableId, &src_ip, sizeof(src_ip));
            return false;
        }

        // update
        client->write(tableId, &src_ip, sizeof(src_ip), value, sizeof(struct dns_record_t));
    }
    catch(...)
    {
        LOG_DEBUG("DNS_LW_DETECTOR RAMCloud Exception: Host not exist %x\n",src_ip);
        return false;
    }    
    return true; 
}

/** @brief Delete timeout records
 * @note This is based on that the linked list is sorted by decreased create_time
 */
void DNS_LW_DETECTOR::del_timeout_records()
{
    LOG_DEBUG("DNS_LW_DETECTOR :: del_timeout_records");
    uint32_t expire_at = Timestamp::now().sec() - _expiration_time;
  
    TableEnumerator iter(*client, tableId, false);

    const void* buffer;
    uint32_t size = 0;

    while(iter.hasNext())
    {
        iter.next(&size, &buffer);

        Object object(buffer, size);

        uint32_t key = *((uint32_t*)object.getKey());
        struct dns_record_t* value = (struct dns_record_t*)object.getValue();
        
        if (value->create_time < expire_at)
        {
            client->remove(tableId, &key, sizeof(key)); 
        }
        LOG_DEBUG("DNS_LW_DETECTOR::RAMCloud: remove key: src %x\n", key);
    
    }
}

void DNS_LW_DETECTOR::run_timer(Timer* timer)
{
    assert(timer == &_timer);
    del_timeout_records();
}

void DNS_LW_DETECTOR::push(int port, Packet *p)
{
   (void) port;
    // LOG("Enter DNS_LW_DETECTOR\n");
    // DNS tunnel detector only interested in dns request

    if(53 == ntohs(p->udp_header()->uh_dport))
    {
        const click_ip *iph = p->ip_header();
        uint32_t sip = iph->ip_src.s_addr;
        // check payload length
        uint32_t payload_len = ntohs(iph->ip_len) - (iph->ip_hl << 2) - sizeof(click_udp);
        if(payload_len > _payload_len_threshold)
        {
            struct dns_record_t* record = NULL;

            if((record = is_Exist(sip)) != NULL)
            {
                record->count ++;
                update_record(sip, record);
            }
            else
            {
                // add new record
                record = (dns_record_t*)malloc(sizeof(dns_record_t));
                if (!record)
                {
                    return;
                }
                record->count = 1;
                record->create_time = Timestamp::now().sec();
                add_record(sip, record);
                free(record);
            }
            set_tag(p, PTAG_DNS_TUNNEL);
        }
    }

    output(0).push(p);
}

DNS_LW_DETECTOR::~DNS_LW_DETECTOR()
{
    delete client;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DNS_LW_DETECTOR)
