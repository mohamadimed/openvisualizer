# Copyright (c) 2010-2013, Regents of the University of California.
# All rights reserved.
#
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License

import json
import logging
import struct
import threading

import networkInfo
import datetime 
from pydispatch import dispatcher
import numpy as np

import paho.mqtt.client as mqtt

from openvisualizer.motehandler.moteconnector.openparser import parser

log = logging.getLogger('ParserData')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())

def init_pkt_info():
    return {
                        'asn'            : 0,
                        'src_id'         : None,
                        'counter'        : 0,
                        'latency'        : 0,
                        'dagRank'        : 0,
                        'maxBufferSize'     : 0,
                        'minBufferSize'     : 0,
                        'numCellsUsedTx' : 0,
                        'numCellsUsedRx' : 0,  
                        }

def init_ugateway_pkt_info():
    return {
                        'asn'            : 0,
                        'src_id'         : None,
                        'rssi'        : 0,
                        'buffer'        : 0,
                        'length'        : 0,
                        'latency'        : 0,
                        'number'        : 0,

                        }
def data_describe (data):
    mean= np.mean(data)
    median = np.median(data)
    std = np.std(data)
    first_q = np.quantile(data, 0.25)
    third_q = np.quantile(data, 0.75)   
    return mean,median,std,min(data),max(data),first_q,third_q;

class ParserData(parser.Parser):
    
    HEADER_LENGTH = 2
    MSPERSLOT      = 0.02 #second per slot.

    IPHC_SAM       = 4
    IPHC_DAM       = 0

    UINJECT_MASK = 'uinject'
    UGATEWAY_MASK   = 'gateway'

    def __init__(self, mqtt_broker_address, mote_port):

        # log
        log.debug("create instance")
        
        # initialize parent class
        super(ParserData, self).__init__(self.HEADER_LENGTH)

        self._asn = [
            'asn_4',  # B
            'asn_2_3',  # H
            'asn_0_1',  # H
        ]

        self.avg_kpi = {}
        self.first_arrival_ts = -1

        self.mote_port = mote_port
        self.broker = mqtt_broker_address
        self.mqtt_connected = False

        if self.broker:

            # connect to MQTT
            self.mqtt_client = mqtt.Client()
            self.mqtt_client.on_connect = self._on_mqtt_connect

            try:
                self.mqtt_client.connect(self.broker)
            except Exception as e:
                log.error("failed to connect to {} with error msg: {}".format(self.broker, e))
            else:
                # start mqtt client
                self.mqtt_thread = threading.Thread(name='mqtt_loop_thread', target=self.mqtt_client.loop_forever)
                self.mqtt_thread.start()

    # ======================== private =========================================

    def _on_mqtt_connect(self, client, userdata, flags, rc):
        log.success("connected to broker ({}) for mote on port: {}".format(self.broker, self.mote_port))

        self.mqtt_connected = True

    # ======================== public ==========================================

    def parse_input(self, data):
        # log
        log.debug("received data {0}".format(data))
        #print("received data {0}".format(data))
        # ensure data not short longer than header
        self._check_length(data)

        _ = data[:2]  # header bytes
        # asn comes in the next 5bytes.

        asn_bytes = data[2:7]
        (self._asn) = struct.unpack('<BHH', ''.join([chr(c) for c in asn_bytes]))

        # source and destination of the message
        dest = data[7:15]

        # source is elided!!! so it is not there.. check that.
        source = data[15:23]

        log.debug("destination address of the packet is {0} ".format("".join(hex(c) for c in dest)))
        log.debug("source address (just previous hop) of the packet is {0} ".format("".join(hex(c) for c in source)))

        # remove asn src and dest and mote id at the beginning.
        # this is a hack for latency measurements... TODO, move latency to an app listening on the corresponding port.
        # inject end_asn into the packet as well
        data = data[23:]

        log.debug("packet without source, dest and asn {0}".format(data))

        # when the packet goes to internet it comes with the asn at the beginning as timestamp.

        # cross layer trick here. capture UDP packet from udpLatency and get ASN to compute latency.
        offset = 0
        if len(data) > 37:
            offset -= 7
            if self.UINJECT_MASK == ''.join(chr(i) for i in data[offset:]):
                print ("received uinject packet")
                print (''.join(chr(i) for i in data[offset:]))
                pkt_info = init_pkt_info()

                pkt_info['counter']      = data[offset-2] + 256*data[offset-1]                   # counter sent by mote
                offset -= 2

                pkt_info['asn']          = struct.unpack('<I',''.join([chr(c) for c in data[offset-5:offset-1]]))[0]
                aux                      = data[offset-5:offset]                               # last 5 bytes of the packet are the ASN in the UDP latency packet
                diff                     = ParserData._asn_diference(aux, asn_bytes)            # calculate difference 
                pkt_info['latency']      = diff                                        # compute time in slots
                offset -= 5
                
                # pkt_info['numCellsUsedTx'] = data[offset-1]
                # offset -=1

                # pkt_info['numCellsUsedRx'] = data[offset-1]
                # offset -=1

                pkt_info['numNeighbors'] = data[offset-1]
                offset -=1

                pkt_info['maxBufferSize'] = data[offset-1]
                offset -=1

                # pkt_info['minBufferSize'] = data[offset-1]
                # offset -=1

                pkt_info['src_id']       = ''.join(['%02x' % x for x in [data[offset-1],data[offset-2]]]) # mote id
                src_id                   = pkt_info['src_id']
                offset -=2

                pkt_info['dagRank']      = struct.unpack('<H',''.join([chr(c) for c in data[offset-2:offset]]))[0]
                offset -=2
                
                numTicksOn               = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4

                numTicksTx               = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4

                numTicksOn_0              = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4

                numTicksTx_0               = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4
                
                numTicksOn_1              = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4

                numTicksTx_1               = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4
                               
                numTicksOn_2              = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4

                numTicksTx_2               = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4
                
                numTicksInTotal          = struct.unpack('<I',''.join([chr(c) for c in data[offset-4:offset]]))[0]
                offset -= 4

                pkt_info['numTicksOn']    = numTicksOn    # duty cycle
                pkt_info['numTicksTx']    = numTicksTx    # duty cycle
                pkt_info['numTicksOn_0']    = numTicksOn_0    # duty cycle
                pkt_info['numTicksTx_0']    = numTicksTx_0    # duty cycle
                pkt_info['numTicksOn_1']    = numTicksOn_1    # duty cycle
                pkt_info['numTicksTx_1']    = numTicksTx_1    # duty cycle
                pkt_info['numTicksOn_2']    = numTicksOn_2    # duty cycle
                pkt_info['numTicksTx_2']    = numTicksTx_2    # duty cycle

                pkt_info['numTicksInTotal']    = numTicksInTotal   # duty cycle

                #print (pkt_info)
                with open('C:\\Users\\bmhg9130\\Desktop\\pkt_info.log'.format(),'a') as f:
                    f.write(str(pkt_info)+'\n')
                    f.close()

                if self.mqtt_connected:
                    self.publish_kpi(src_id,pkt_info)

                # in case we want to send the computed time to internet..
                # computed=struct.pack('<H', timeinus)#to be appended to the pkt
                # for x in computed:
                # data.append(x)

            elif (self.UGATEWAY_MASK == ''.join(chr(i) for i in data[offset:])):
                print ("received ugw packet")
                print (data)
                pkt_info = init_ugateway_pkt_info()

                pkt_info['counter']      = data[offset-2] + 256*data[offset-1]                   # counter sent by mote
                offset -= 2

                pkt_info['asn']          = struct.unpack('<I',''.join([chr(c) for c in data[offset-5:offset-1]]))[0]
                aux                      = data[offset-5:offset]                               # last 5 bytes of the packet are the ASN in the UDP latency packet
                diff                     = self._asndiference(aux,asnbytes)            # calculate difference 
                pkt_info['latency']      = diff                                        # compute time in slots
                offset -= 5

                pkt_info['src_id']       = ''.join(['%02x' % x for x in [data[offset-1],data[offset-2]]]) # mote id
                src_id                   = pkt_info['src_id']
                offset -=2

                pkt_info['length'] = data[offset-1]
                offset -=1
                pkt_info['number'] = data[offset-1]
                offset -=1
                pkt_info['rssi'] = data[offset-1]
                offset -=1

                print (pkt_info)
            else:
                # no udplatency
                # print data
                pass
        else:
            pass

        event_type = 'data'
        # notify a tuple including source as one hop away nodes elide SRC address as can be inferred from MAC layer
        # header
        return event_type, (source, data)

    # ======================== private =========================================

    @staticmethod
    def _asn_diference(init, end):

        asn_init = struct.unpack('<HHB', ''.join([chr(c) for c in init]))
        asn_end = struct.unpack('<HHB', ''.join([chr(c) for c in end]))
        if asn_end[2] != asn_init[2]:  # 'byte4'
            return 0xFFFFFFFF
        else:
            pass

        return 0x10000 * (asn_end[1] - asn_init[1]) + (asn_end[0] - asn_init[0])

    # ========================== mqtt publish ====================================

    def publish_kpi(self, src_id,pkt_info):

        payload = {'token': 123}

        payload['src_id']          = src_id

         #print payload
        payload ['rpl_phy_stats'] = networkInfo.rpl_radio_stats
        payload ['rpl_node_count']= networkInfo.rpl_nodes_count
        payload ['rpl_churn']=networkInfo.rpl_churn
        if (networkInfo.set_root_timestamp !=0):
            delta= datetime.datetime.now() - networkInfo.set_root_timestamp
            payload ['time_elapsed']= {
            'seconds': delta.seconds, 
            'microseconds':delta.microseconds
            }        
        else: 
            delta= datetime.datetime.now()

        payload ['pkt_info'] = pkt_info

        with open('C:\\Users\\bmhg9130\\Desktop\\kpi_info.log'.format(),'a') as f:
                    f.write(str(payload)+'\n')
                    f.close()

        if self.mqtt_connected:
            # publish the cmd message
            self.mqtt_client.publish(topic='opentestbed/uinject/arrived', payload=json.dumps(payload), qos=2)
            print("published")
        else: 
            print("not published")