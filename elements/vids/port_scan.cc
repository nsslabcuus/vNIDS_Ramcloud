#include <click/config.h>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/logger.h>

#include <stdio.h>
#include <ramcloud/TableEnumerator.h>
#include <ramcloud/ClientException.h>

#include "port_scan.hh"

CLICK_DECLS

PortScan::PortScan(): _expiration_time(300), _ramserver(""), _ramname(""), _timer(this), client(NULL)
{
}
PortScan::~PortScan() 
{
    delete client;
}

int
PortScan::initialize(ErrorHandler*)
{
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

int
PortScan::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int ret = Args(conf, this, errh).read("expire", _expiration_time)
              .read("ramserver", _ramserver)
              .read("ramname", _ramname)
              .execute();

    if (_ramserver.empty() || _ramname.empty())
    {
         LOGE("Init failed due to ramcloud server or name are not configured! %s %s", _ramserver.c_str(), _ramname.c_str());
         return -EINVAL;
    }

    client = new RamCloud(_ramserver.c_str(), _ramname.c_str());

    try
    {
        tableId = client->getTableId("PortScan");
    
    }
    catch(...)
    {
        LOG_DEBUG("Table PortScan Does not Exist! Create new one!");
        // create table
        tableId = client->createTable("PortScan", 2); 
    }

    return ret;
}

void
PortScan::run_timer(Timer* timer)
{
    assert(timer == &_timer);
    delete_timeout_record();
}

struct portscan_record*
PortScan::is_Exist(uint64_t src_ip) 
{
    Buffer buffer;
    try
    {
        client->read(tableId, &src_ip, sizeof(src_ip), &buffer); 
    }
    catch(...)
    {
        LOG_DEBUG("PortScan RAMCloud Exception: Host not exist %lu\n",src_ip);
        return NULL;
    }
    return static_cast<struct portscan_record*>(buffer.getRange(0, buffer.size()));
}
bool
PortScan::add_record(uint64_t src_ip, struct portscan_record* value)
{
    try
    {
        client->write(tableId, &src_ip, sizeof(uint64_t), value , sizeof(struct portscan_record));
    }
    catch(...)
    {
        LOG_DEBUG("PortScan RamCloudException: Add portscan record failed: src %lu\n", src_ip);
        return false;
    }
    LOG_DEBUG("PortScan RAMCloud Add portscan record sucessfully: src %lu\n", src_ip);
     
    return true;
}

void
PortScan::delete_timeout_record()
{

    LOG_DEBUG("PortScan :: del_timeout_records");
    uint32_t expire_at = Timestamp::now().sec() - _expiration_time;
  
    TableEnumerator iter(*client, tableId, false);

    const void* buffer;
    uint32_t size = 0;

    while(iter.hasNext())
    {
        iter.next(&size, &buffer);

        Object object(buffer, size);

        uint64_t key = *((uint64_t*)object.getKey());
        struct portscan_record* value = (struct portscan_record*)object.getValue();
        
        /*
        if (value->hostsize == MAX_HOST || value->portsize == MAX_PORT)
        {
            // operation for portscan candidate
            LOG_EVAL("Suspicious Port Scan Host %lu, scanned hosts and ports size : %d %d\n", key, value->hostsize, value->portsize);
            value->hostsize ++, value->portsize ++; 
            return;
        } 
        */
        if (value->last_time < expire_at)
        {
            client->remove(tableId, &key, sizeof(key)); 
        }
        LOG_DEBUG("PortScan::RAMCloud: remove key: src %lu\n", key);
    
    }
}

void
PortScan::update_record(uint64_t src_ip, struct portscan_record* record)
{
    if (!record)
    {
        return;
    }

    try
    {
        client->write(tableId, &src_ip, sizeof(uint64_t), record, sizeof(struct portscan_record));
    }
    catch(...)
    {
        LOG_DEBUG("PortScan RamCloudException: update portscan record failed: src %lu\n", src_ip);
        return;
    }
    LOG_DEBUG("PortScan RAMCloud update portscan record sucessfully: src %lu\n", src_ip);

}

void 
PortScan::push(int port, Packet* p)
{
    (void)port;
    // uint16_t src_port = -1, 
    uint16_t dst_port = -1;
    const click_ip* ip = p->ip_header();
    uint64_t src_ip = (ip->ip_src).s_addr;
    uint64_t dst_ip = (ip->ip_dst).s_addr;

    if(IP_PROTO_TCP == ip->ip_p)
    {
        // src_port = ntohs(p->tcp_header()->th_sport);
        dst_port = ntohs(p->tcp_header()->th_dport);
    }
    else if(IP_PROTO_UDP == ip->ip_p)
    {
        // src_port = ntohs(p->udp_header()->uh_sport);
        dst_port = ntohs(p->udp_header()->uh_dport);
    }
     
    struct portscan_record* record = NULL;
    if ((record = is_Exist(src_ip)) != NULL)
    {
        record->last_time = Timestamp::now().sec();
        record->packetcounter += 1;
        record->packetsizecounter += ntohs(ip->ip_len);
        
        if (record->hostsize == MAX_HOST || record->portsize == MAX_PORT)
        {
            // port scan candidate
            LOG_EVAL("Suspicious Port Scan Host %lu, scanned hosts and ports size : %d %d\n", src_ip, record->hostsize, record->portsize);
            record->hostsize++, record->portsize ++;
            return;
        }

        int i = 0;
        for (; i < record->hostsize; ++i)
        {
            if (record->hosts[i] == dst_ip)
            {
                break;
            }
        }
        if (i >= record->hostsize)
        {
            record->hosts[i] = dst_ip;
            record->hostsize ++;
        }
        i = 0;
        for (; i < record->portsize; ++i)
        {
            if (record->ports[i] == dst_port)
            {
                break;
            }
        }
        if (i >= record->portsize)
        {
            record->ports[i] = dst_port;
            record->portsize ++;
        }


        update_record(src_ip, record);
    }
    else
    {
        record = (struct portscan_record*)malloc(sizeof(struct portscan_record));
        
        record->last_time = Timestamp::now().sec();
        record->create_time = record->last_time;
        record->packetcounter = 1;
        record->packetsizecounter = ntohs(ip->ip_len);
        record->hosts[0] = dst_ip;
        record->ports[0] = dst_port;
        record->portsize = 1;
        record->hostsize = 1;

        // add new record
        add_record(src_ip, record);

        free(record);
    }

    output(0).push(p); 
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PortScan)
ELEMENT_MT_SAFE(PortScan)

