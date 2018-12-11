#include <click/config.h>
#include <click/args.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/logger.h>

#include <stdio.h>
#include <ramcloud/TableEnumerator.h>
#include <ramcloud/ClientException.h>

#include "per_flow_analysis.hh"

CLICK_DECLS

PerFlowAnalysis::PerFlowAnalysis(): _expiration_time(300), _ramserver(""), _ramname(""),  _timer(this), client(NULL) 
{
}

PerFlowAnalysis::~PerFlowAnalysis()
{
    delete client;
}

int
PerFlowAnalysis::initialize(ErrorHandler*)
{
    _timer.initialize(this);
    _timer.schedule_now();
    return 0;
}

int
PerFlowAnalysis::configure(Vector<String> &conf, ErrorHandler *errh)
{
    cnt = 0;
    int ret = Args(conf, this, errh)
              .read("expire", _expiration_time)
              .read("cnt", cnt)
              .read("ramserver", _ramserver)
              .read("ramname", _ramname)
              .execute();

    if (_ramserver.empty() || _ramname.empty())
    {
         LOGE("Init failed due to ramcloud server or name are not configured! %s %s", _ramserver.c_str(), _ramname.c_str());
         return -EINVAL;
    }

    client = new RamCloud(_ramserver.c_str(), _ramname.c_str());
    

    std::string qname = "PerflowAnalysis";

    char* name = (char*)malloc(qname.size()+sizeof(cnt)+1);

    sprintf(name, "%s%d", qname.c_str(), cnt);
    try
    {
        // create table
        tableId = client->getTableId(name);
        // client->dropTable(name);
    }
    catch(...)
    {
        LOG("Table PerflowAnalysis Does not Exist! Create new one");
        // create table
        tableId = client->createTable(name, 2);
    }
 
    return ret;
}

void
PerFlowAnalysis::run_timer(Timer* timer)
{
    assert(timer == &_timer);
    delete_timeout_record();
}

struct perflow_value*
PerFlowAnalysis::is_Exist(struct perflow_key* pkey) 
{
    Buffer buffer;
    try
    {
        client->read(tableId, pkey, sizeof(struct perflow_key), &buffer); 
    }
    catch(...)
    {
        LOG("PerflowAnalysis RAMCloud Exception: flow not exist %x %d %x %d\n",pkey->src_ip, pkey->src_port, pkey->dst_ip, pkey->dst_port);
        return NULL;
    }
    return static_cast<struct perflow_value*>(buffer.getRange(0, buffer.size()));
}
bool
PerFlowAnalysis::add_record(struct perflow_key* pkey, struct perflow_value* pvalue)
{
    try
    {
        client->write(tableId, pkey, sizeof(struct perflow_key), pvalue , sizeof(struct perflow_value));
    }
    catch(...)
    {
        LOG("PerflowAnalysis RamCloudException: Add perflow record failed: src %x %d dst %x %d.\n",
                 pkey->src_ip, pkey->src_port, pkey->dst_ip, pkey->dst_port);
        return false;
    }
    LOG_DEBUG("PerflowAnalysis RAMCloud Add perflow record sucessfully: src %x %d dst %x %d\n",
                 pkey->src_ip, pkey->src_port, pkey->dst_ip, pkey->dst_port);
     
    return true;
}

void
PerFlowAnalysis::delete_timeout_record()
{
    LOG_DEBUG("PerflowAnalysis::del_timeout_records");
    uint32_t expire_at = Timestamp::now().sec() - _expiration_time;
    TableEnumerator iter(*client, tableId, false);

    const void* buffer;
    uint32_t size = 0;

    while(iter.hasNext())
    {
        iter.next(&size, &buffer);

        Object object(buffer, size);

        struct perflow_key* flowKey = (struct perflow_key*)object.getKey();
        struct perflow_value* flowValue = (struct perflow_value*)object.getValue();

        if (flowValue->last_time < expire_at)
        {
            client->remove(tableId, flowKey, sizeof(flowKey)); 
        }
        LOG_DEBUG("RAMCloud: remove key: src %x %d dst %x %d, value : time %d %d  count %d size %d \n",
                 flowKey->src_ip, flowKey->src_port, flowKey->dst_ip, flowKey->dst_port,
                 flowValue->last_time, flowValue->create_time, flowValue->packetcounter, flowValue->packetsizecounter);
    
    }
}
void 
PerFlowAnalysis::push(int port, Packet* p)
{
    (void)port;
    uint16_t src_port = -1, dst_port = -1;
    const click_ip* ip = p->ip_header();
    uint32_t src_ip = (ip->ip_src).s_addr;
    uint32_t dst_ip = (ip->ip_dst).s_addr;
    
    if(IP_PROTO_TCP == ip->ip_p)
    {
        src_port = ntohs(p->tcp_header()->th_sport);
        dst_port = ntohs(p->tcp_header()->th_dport);
    }
    else if(IP_PROTO_UDP == ip->ip_p)
    {
        src_port = ntohs(p->udp_header()->uh_sport);
        dst_port = ntohs(p->udp_header()->uh_dport);
    }
    
    struct perflow_key* pkey = (struct perflow_key*)malloc(sizeof(struct perflow_key));
    pkey->src_ip = src_ip;
    pkey->src_port = src_port;
    pkey->dst_ip = dst_ip;
    pkey->dst_port = dst_port;

   
    struct perflow_value* existValue = NULL;
    if ((existValue = is_Exist(pkey)) != NULL)
    {
        existValue->last_time = Timestamp::now().sec();
        existValue->packetcounter += 1;
        existValue->packetsizecounter += ntohs(ip->ip_len);
        client->write(tableId, pkey, sizeof(pkey), existValue, sizeof(existValue));
        LOG_DEBUG("RAMCloud: update key: src %x %d dst %x %d, value : time %d %d  count %d size %d \n",
                 pkey->src_ip, pkey->src_port, pkey->dst_ip, pkey->dst_port,
                 existValue->last_time, existValue->create_time, existValue->packetcounter, existValue->packetsizecounter);
    
    }
    else
    {
        // add new record
        struct perflow_value* pvalue = (struct perflow_value*)malloc(sizeof(struct perflow_value));
        pvalue->last_time = Timestamp::now().sec();
        pvalue->create_time = pvalue->last_time;
        pvalue->packetcounter = 1;
        pvalue->packetsizecounter = ntohs(ip->ip_len);
     
        add_record(pkey, pvalue);

        free(pvalue);
    }
    free(pkey);

    output(0).push(p); 
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PerFlowAnalysis)
ELEMENT_MT_SAFE(PerFlowAnalysis)

