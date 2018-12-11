/*
 * DNSTUNNELS.{cc,hh} -- element used to detect dns tunnels attack 
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
//#include <click/args.hh>
#include <clicknet/ip.h>
#include <click/logger.h>
#include <click/config.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/dns.h>
#include <click/timer.hh>
#include <click/packet_anno.hh>

#include <ramcloud/TableEnumerator.h>
#include <ramcloud/ClientException.h>

#include "event.hh"
#include "datamodel.hh"
#include "dnstunnels.hh"
#include "dnsanalyzer.hh"

CLICK_DECLS

DNSTUNNELS::DNSTUNNELS()
{
    client = new RamCloud("tcp:host=10.0.127.2,port=11100", "__unnamed__");
    try
    {
        tableId = client->getTableId("DNSTUNNELS");
    }
    catch(...)
    {
        LOG("Table DNSTUNNELS Does not Exist! Create new one!");
        // create table
        tableId = client->createTable("DNSTUNNELS", 2);
    }
}

DNSTUNNELS::~DNSTUNNELS()
{
    delete client;
}

int
DNSTUNNELS::configure(Vector<String> &, ErrorHandler *)
{
    return 0;
}

// Check if the host ip is exists in the record
dnstunnels_record* 
DNSTUNNELS::is_Exist(uint32_t src_ip)
{
    Buffer buffer;
    try
    {
        client->read(tableId, &src_ip, sizeof(src_ip), &buffer); 
    }
    catch(...)
    {
        LOG("DNSTUNNELS RAMCloud Exception: Host not exist %x\n",src_ip);
        return NULL;
    }
    return static_cast<dnstunnels_record*>(buffer.getRange(0, buffer.size()));
}

// Use head insert
bool
DNSTUNNELS::add_record(uint32_t host_ip, uint32_t create)
{
    dnstunnels_record* record = (dnstunnels_record *)malloc(sizeof(dnstunnels_record));
    if(record)
    {
        record->count = 1;
        record->create_time = create;
        try
        {
            client->write(tableId, &host_ip, sizeof(uint32_t), record, sizeof(dnstunnels_record));
        }
        catch(...)
        {
            LOG("DNSTUNNELS RamCloudException: Add record failed: src %x\n", host_ip);
            free(record);
            return false;
        }
        LOGE("DNSTUNNELS RAMCloud Add record sucessfully: src %x\n", host_ip);
        free(record);
        return true;
    }
    free(record);
    return false;
}

bool
DNSTUNNELS::delete_record(uint32_t host_ip)
{
    try
    {
        client->remove(tableId, &host_ip, sizeof(uint32_t));
    }
    catch(...)
    {
        LOG("DNSTUNNELS RamCloudException: remove record failed: %x\n", host_ip);
        return false;
    }

    return true;
}

Packet *
DNSTUNNELS::pull(int port)
{
    (void) port;

    Packet *p = input(0).pull();
    if(p == NULL)
    {
        return NULL;
    }
    dnstunnels_record *record = NULL;
    event_t *_event = extract_event(p);
    DNSDataModel model(_event->data);
    if(model.validate(_event->data + _event->event_len))
    {
        uint32_t ip = get_value<DNSDataModel, DNS_FIELD_RECORD_IP>(model);
        char *qname = get_field<DNSDataModel, DNS_FIELD_QNAME>(model);

        record = is_Exist(ip);         
        if(!record)
        {
            add_record(ip, (uint32_t)Timestamp::now().sec());
            return p;
        }
        //Check if the record is expired
        if((uint32_t)Timestamp::now().sec() - record->create_time > DNSTUNNELS_EXPIRATION)
        {
            delete_record(ip);
            LOGE("record deleted!");
            record = NULL;
            return p;
        }

        record->count++;
        if(record->count > COUNT_THRESHOLD)
        {
            delete_record(ip);
            LOGE("Suspicious! record count is %d", record->count);
            return p;
        }
        else
        {
            int query_len = strlen(qname);
            int i = 0;
            int num_count = 0;
            LOGE("query len is %d", query_len);
            if(query_len > DNSTUNNELS_QUERY_LEN_THRESHOLD)
            {
                for(i=0; i<query_len; i++)
                {
                    if(qname[i] > '0' && qname[i] < '9')
                        num_count++;
                }
            }

            if(num_count*10/query_len > PERCENTAGE_OF_COUNT)
            {
                LOGE("Suspicious! Numberical charicter overload");
                return p;
            }
        }
    }
    else
    {
        LOGE("DataModel invalid!");
    }
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DNSTUNNELS)
ELEMENT_MT_SAFE(DNSTUNNELS)
