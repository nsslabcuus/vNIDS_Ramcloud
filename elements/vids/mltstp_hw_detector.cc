/*
 * MLTSTP_HW_DETECTOR.{cc,hh} -- element used to detect trojan detector 
 * HHZZK 
 *
 * Copyright (c) 2008 HHZZK.
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

#include <ramcloud/TableEnumerator.h>
#include <ramcloud/ClientException.h>

#include "event.hh"
#include "datamodel.hh"
#include "mltstp_hw_detector.hh"

CLICK_DECLS

MLTSTP_HW_DETECTOR::MLTSTP_HW_DETECTOR()
{
}

MLTSTP_HW_DETECTOR::~MLTSTP_HW_DETECTOR()
{
    delete client;
}

int MLTSTP_HW_DETECTOR::configure(Vector<String> &conf, ErrorHandler *errh)
{
    int ret = Args(conf, this, errh)
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
        client->dropTable("MLTSTP_HW_DETECTOR");
    }
    catch(...)
    {
        LOG("Table MLTSTP_HW_DETECTOR Does not Exist");
    }
    // create table
    tableId = client->createTable("MLTSTP_HW_DETECTOR", 2); 

    return ret;
}

int
MLTSTP_HW_DETECTOR::initialize(ErrorHandler *)
{
    return 0;
}

// Check if the ip is exists in the record
mltstp_hw_records* 
MLTSTP_HW_DETECTOR::is_Exist(uint32_t ip)
{
    Buffer buffer;
    try
    {
        client->read(tableId, &ip, sizeof(ip), &buffer); 
    }
    catch(...)
    {
        LOG("MLTSTP_HW_DETECTOR RAMCloud Exception: ip not exist %x\n", ip);
        return NULL;
    }
    return static_cast<mltstp_hw_records*>(buffer.getRange(0, buffer.size()));
}

// Use head insert
void
MLTSTP_HW_DETECTOR::add_record(uint32_t ip, mltstp_hw_records* record)
{
    try
    {
        client->write(tableId, &ip, sizeof(ip), record, sizeof(mltstp_hw_records));
    }
    catch(...)
    {
        LOG("MLTSTP_HW_DETECTOR RamCloudException: Add record failed: ip %x\n", ip);
    }
    LOGE("MLTSTP_HW_DETECTOR RAMCloud Add record sucessfully: ip %x\n", ip);
   
}

void
MLTSTP_HW_DETECTOR::delete_record(uint32_t ip)
{
    try
    {
        client->remove(tableId, &ip, sizeof(ip));
    }
    catch(...)
    {
        LOG("MLTSTP_HW_DETECTOR RamCloudException: remove record failed: ip %x\n", ip);
    }
    LOGE("MLTSTP_HW_DETECTOR RAMCloud remove record sucessfully: ip %x\n", ip);
}

Packet *
//MLTSTP_HW_DETECTOR::pull(int port)
MLTSTP_HW_DETECTOR::simple_action(Packet *p)
{
    //Packet *p = input(0).pull();
    if(p == NULL)
    {
        LOGE("Package is null");
        return NULL;
    }

    mltstp_hw_records* record = NULL;
    event_t *_event = extract_event(p);
    if(_event)
    {
        uint32_t ip;         
        if(_event->event_type == SSH_AUTH_ATTEMPED)
        {
            ip = (uint32_t)_event->connect.src_ip.s_addr;

            record = is_Exist(ip);
            LOG("STEP 1");
            if(!record)
            {
                record = (mltstp_hw_records *)malloc(sizeof(mltstp_hw_records));       

                record->create_time = (uint32_t)Timestamp::now().sec();               
                record->steps = 2;
                add_record(ip, record);

                free(record);
            }
        }
        
        else if(_event->event_type == HTTP_RESPONSE_ZIP)
        {
            ip = (uint32_t)_event->connect.dst_ip.s_addr;

            record = is_Exist(ip);
            if(record)
            {
                LOG("STEP 2");
                if(record->steps == 2)
                {
                    record->steps = 3;
                    add_record(ip, record); 
                }
            }
        }
        else if(_event->event_type == FTP_DOWNLOAD_ZIP)
        {
            ip = (uint32_t)_event->connect.dst_ip.s_addr;

            record = is_Exist(ip);
            if(record)
            {
                if(record->steps == 3)
                {
                    LOGE("Mutistep Attack!!");
                    delete_record(ip);
                }
            }
        }
        else
        {
            LOGE("Error event type");
        }
    }
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MLTSTP_HW_DETECTOR)
ELEMENT_MT_SAFE(MLTSTP_HW_DETECTOR)
