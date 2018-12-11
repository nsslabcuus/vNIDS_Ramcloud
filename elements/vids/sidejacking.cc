/*
 * SIDEJACKING.{cc,hh} -- element used to detect trojan detector 
 * HHZZK 
 *
 * Copyright (c) 2017 HHZZK
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <stdio.h>
#include <clicknet/ip.h>
#include <click/config.h>
#include <click/args.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/logger.h>
#include <click/packet_anno.hh>

#include "event.hh"
#include "datamodel.hh"
#include "sidejacking.hh"
#include "httpanalyzer.hh"

CLICK_DECLS

SIDEJACKING::SIDEJACKING()
{
}

SIDEJACKING::~SIDEJACKING()
{
    delete client;
}

int SIDEJACKING::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int ret =  Args(conf, this, errh)
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
        client->getTableId("SIDEJACKING");
    }
    catch(...)
    {
        LOG("Table SIDEJACKING Does not Exist! Create new one!");
        // create table
        tableId = client->createTable("SIDEJACKING", 2);     
    }

    return ret;
}
int
SIDEJACKING::initialize(ErrorHandler *)
{
    return 0;
}

// Check if the record is exists (cookie as index)
sidejacking_record* 
SIDEJACKING::is_Exist(char* cookie)
{
    Buffer buffer;
    try
    {
        client->read(tableId, cookie, strlen(cookie)+1, &buffer); 
    }
    catch(...)
    {
        LOG("SIDEJACKING RAMCloud Exception: cookie not exist %s\n", cookie);
        return NULL;
    }
    return static_cast<sidejacking_record*>(buffer.getRange(0, buffer.size()));
}

// Use head insert
bool
SIDEJACKING::add_record(char *cookie, sidejacking_record* record)
{
    if (!record)
    {
        return false;
    }
    try
    {
        client->write(tableId, cookie, strlen(cookie), record , sizeof(sidejacking_record));
    }
    catch(...)
    {
        LOGE("SIDEJACKING RAMCloud Add cookie %s failed, ip = %u, agent = %s\n", cookie, record->ip, record->user_agent);
        return false;
    }
    LOGE("SIDEJACKING RAMCloud Add cookie %s sucessfully, ip = %u, agent = %s\n", cookie, record->ip, record->user_agent);
    
    return true;
}

void
SIDEJACKING::push(int port, Packet* p)
{
    (void) port;

    if(p == NULL)
    {
        LOGE("Package is null");
        return ;
    }

    sidejacking_record* record = NULL;
    event_t *_event = extract_event(p);
    HttpDataModel model(_event->data);
    if(model.validate(_event->data + _event->event_len))
    {
        char* cookie = get_field<HttpDataModel, HTTP_FIELD_COOKIE>(model);
        LOGE("Sidejacking: model get cookie: %s", cookie);
        char* user_agent = get_field<HttpDataModel, HTTP_FIELD_USRAGENT>(model);
        LOGE("Sidejacking: model get useragent: %s", user_agent);

        uint32_t ip = (uint32_t)_event->connect.src_ip.s_addr;

        record = is_Exist(cookie); 
        if(!record)
        {
            record = (sidejacking_record *)malloc(sizeof(sidejacking_record));
            if(record)
            {
                record->user_agent = (char *) malloc(strlen(user_agent));
                strcpy(record->user_agent, user_agent);
                record->ip = ip;

                add_record(cookie, record);
                
                free(record);
            }
        }
        else if(ip == record->ip)
        {
            strcpy(record->user_agent, user_agent);
            LOGE("Session cookie reuse: cookie = %s, ip = %u, user agent = %s", cookie, ip, user_agent);
            add_record(cookie, record);
        }
        else
        {
            //LOGE("Record info : cookie = %s, ip = %u, user agent = %s", record->cookie, record->ip, record->user_agent);
            if(strncmp(record->user_agent, user_agent, strlen(user_agent)) == 0) 
            {
                if(DHCP_CONTEXT_AVALIABLE)
                {
                    LOGE("DHCP avaliable");
                }
                else
                {
                    LOGE("DHCP not avaliable");
                }
            }
            else
            {
                LOGE("Alarm sidejacking!!!: cookie = %s, ip = %u, user agent = %s", cookie, ip, user_agent);
            }
        }

        free(cookie);
        free(user_agent);
    }
    else
    {
        LOGE("Sidejacking: the DataModel is invalid for the data, field len %d", (int)model.len());
    }
    output(0).push(p);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SIDEJACKING)
ELEMENT_MT_SAFE(SIDEJACKING)
