# Copyright (c) 2010-2013, Regents of the University of California.
# All rights reserved.
#
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License

import logging
import threading

from pydispatch import dispatcher

log = logging.getLogger('EventBusClient')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())


class EventBusClient(object):
    WILDCARD = '*'

    PROTO_ICMPv6 = 'icmpv6'
    PROTO_UDP = 'udp'
    PROTO_ALL = [
        PROTO_ICMPv6,
        PROTO_UDP,
    ]

    def __init__(self, name, registrations):

        assert type(name) == str
        assert type(registrations) == list
        for r in registrations:
            assert type(r) == dict
            for k in r.keys():
                assert k in ['signal', 'sender', 'callback']

        # log
        log.debug("create instance")
        #print("create instance {}".format(name))
        # store params
        self.data_lock = threading.RLock()
        self.registrations = []

        # give this thread a name
        self.name = name

        # local variables
        self.go_on = True

        # register registrations
        for r in registrations:
            self.register(sender=r['sender'], signal=r['signal'], callback=r['callback'])

        # connect to dispatcher
        dispatcher.connect(receiver=self._event_bus_notification)

    # ======================== public ==========================================

    def dispatch(self, signal, data):
        #print("--*--DISPATCH sending SIgnal {} for DATA {}".format(signal,data))
        ret = dispatcher.send(sender=self.name, signal=signal, data=data)
        #print ('/////////////////////////// RETURNU IS {}'.format(ret))
        return ret #dispatcher.send(sender=self.name, signal=signal, data=data)

    def register(self, sender, signal, callback):

        # detect duplicate registrations
        with self.data_lock:
            for reg in self.registrations:
                if reg['sender'] == sender and reg['signal'] == signal and reg['callback'] == callback:
                    raise SystemError(
                        "Duplicate registration of sender={0} signal={1} callback={2}".format(
                            sender,
                            signal,
                            callback,
                        ),
                    )

        # register
        new_registration = {
            'sender': sender,
            'signal': signal,
            'callback': callback,
            'numRx': 0,
        }

        with self.data_lock:
            self.registrations += [new_registration]

    def unregister(self, sender, signal, callback):

        with self.data_lock:
            for reg in self.registrations:
                if reg['sender'] == sender and self._signals_equivalent(reg['signal'], signal) and \
                        reg['callback'] == callback:
                    self.registrations.remove(reg)

    # ======================== private =========================================

    def _event_bus_notification(self, signal, sender, data):
        #if (signal == 'getSourceRoute'):
        #print("--*--EBUS NOTIF {}  from {}".format(signal,sender))
            #print('+++ AVAILABLE Registrations for {} === {}'.format(self,len(self.registrations)))
        callback = None

        # find the callback
        with self.data_lock:
            #print("REG size ============ {}".format(len(self.registrations)))
            for r in self.registrations:
                #if (signal == 'getSourceRoute'):
                    #print("*********Available SIG = {} / SIG = {} and available Sender is {}/ Sender = {}".format(r['signal'],signal,r['sender'],sender))
                if self._signals_equivalent(r['signal'], signal) and (
                        r['sender'] == sender or r['sender'] == self.WILDCARD):
                    callback = r['callback']
                    break
            
        if not callback:
            return None

        # call the callback
        try:
            return callback(sender=sender, signal=signal, data=data)
        except TypeError as err:
            output = "ERROR could not call {0}, err={1}".format(callback, err)
            log.critical(output)
            print output

    def _signals_equivalent(self, s1, s2):
        return_val = True
        if type(s1) == type(s2) == str:
            if (s1 != s2) and (s1 != self.WILDCARD) and (s2 != self.WILDCARD):
                return_val = False
        elif type(s1) == type(s2) == tuple:
            if len(s1) == len(s2) == 3:
                for i in range(3):
                    if (s1[i] != s2[i]) and (s1[i] != self.WILDCARD) and (s2[i] != self.WILDCARD):
                        return_val = False
            else:
                return_val = False
        else:
            return_val = False
        #print('VAL VALUE {}'.format(return_val))
        return return_val

    def _dispatch_protocol(self, signal, data):
        """ used to sent to the eventbus a signal and look whether someone responds or not"""
        temp = self.dispatch(signal=signal, data=data)
        for (function, return_val) in temp:
            if return_val is not None:
                if log.isEnabledFor(logging.DEBUG):
                    log.debug("returning true is subscribed to signal {0}, {1}".format(signal, return_val))
                    #log.success("----true")
                return True

        if log.isEnabledFor(logging.DEBUG):
            log.debug("returning false as nobody is subscribed to signal {0}, {1}".format(signal, temp))
            #log.success("----false")

        return False

    def _dispatch_and_get_result(self, signal, data):
        #print('Dis REC  {} -- {} ---------------{}'.format(self,signal,data))
        #if (signal == 'getSourceRoute'):
            #print('****************************HEEEEEEEERE from {}'.format(self))
        temp = self.dispatch(signal=signal, data=data)
        for (function, return_val) in temp:
            if return_val is not None:
                return return_val
        raise SystemError('No answer to signal _dispatch_and_get_result')
