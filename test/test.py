# Copyright (c) 2010-2013, Regents of the University of California.
# All rights reserved.
#
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License

"""
Module which coordinates rpl DIO and DAO messages.

.. module author:: Xavi Vilajosana <xvilajosana@eecs.berkeley.edu>
                  January 2013
.. module author:: Thomas Watteyne <watteyne@eecs.berkeley.edu>
                  April 2013
"""

import logging
import os
import threading

from appdirs import user_data_dir

from openvisualizer.eventbus import eventbusclient
from openvisualizer.rpl import sourceroute
from openvisualizer.utils import format_addr, format_buf, format_ipv6_addr

log = logging.getLogger('RPL')
log.setLevel(logging.ERROR)
log.addHandler(logging.NullHandler())


class TEST(eventbusclient.EventBusClient):
  

    def __init__(self):

        # log
        log.debug("create instance")

        # initialize parent class
        eventbusclient.EventBusClient.__init__(
            self,
            name='test',
            registrations=[]
        )

    def _get_source_route(self, destination):
        return_val = self._dispatch_and_get_result(signal='getSourceRoute', data=destination)
        return return_val


    def _get_route(self, destination=[0x00, 0x12, 0x4b, 0x00, 0x14, 0xb5, 0xd3, 0x2f])
        print('++++trying to get Destionation++')
        dest = self._get_source_route(destination)
        print('++++ Dest == {}'.format(dest))
        return dest