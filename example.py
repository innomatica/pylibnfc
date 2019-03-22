#!/usr/bin/env python3

import binascii
import queue
import threading
import time

from nfc import *

keyTagId = '16 60 1e d9'
msgQueue = queue.Queue(100)
cmdQueue = queue.Queue(100)

class NFCReader(threading.Thread):

    def __init__(self, nt, pnd):
        threading.Thread.__init__(self)

        # nfc_target structure
        self.nt = nt
        # device
        self.pnd = pnd
        # store previous id
        self.nfcId = ""

        # poll for a type A (MIFARE) tag
        self.nmMifare = nfc_modulation()
        self.nmMifare.nmt = NMT_ISO14443A
        self.nmMifare.nbr = NBR_106

    def run(self):

        while True:
            # poll for target tags: assume that there is only one
            if nfc_initiator_select_passive_target(self.pnd, self.nmMifare,
                    None, 0, pointer(self.nt)) > 0:

                # convert id number array into string
                nfcId = "".join('{:02x} '.format(self.nt.nti.nai.abtUid[i])
                        for i in range(self.nt.nti.nai.szUidLen))
                # get rid of trailing whitespaces
                nfcId = nfcId.rstrip()

                # if the id is different from the previous one
                if nfcId != self.nfcId:
                    # then report it to main
                    msgQueue.put(nfcId)
                    # now remember new id
                    self.nfcId = nfcId
                    # wait for the command from the main
                    cmd = cmdQueue.get()
                    # stop requested
                    if cmd == 'stop':
                        # terminate the thread
                        break

                # if the same id tag is detected
                else:
                    # take a short break here
                    time.sleep(3)



if __name__=="__main__":

    # nfc_target structure
    nt = nfc_target()
    # nfc context structure
    context = pointer(nfc_context())

    # initialize the driver and get the context
    nfc_init(byref(context))

    if context is None:
        print("Unable to init libnfc (malloc)")
        exit()

    # open nfc driver using the contrext
    pnd = nfc_open(context, None)

    if pnd is None:
        print("Unable to open NFC device")
        nfc_exit(context)
        exit()

    # initialize the iniitator
    if nfc_initiator_init(pnd) < 0:
        nfc_perror(pnd, "nfc_initiator_init")
        nfc_exit(context)
        exit()

    print('NFC reader: {} opened'.format(nfc_device_get_name(pnd).decode()))

    # tag polling thread
    nfcThread = NFCReader(nt, pnd)
    # start
    nfcThread.start()

    while True:
        try:
            # this is nonblocking
            msg = msgQueue.get(False)
        except:
            # so prepare Exception
            time.sleep(1)
        else:
            # key tag is detected
            if msg == keyTagId:
                # ask thread to terminate
                cmdQueue.put('stop')
                print('key tag detected.... bye')
                # lets get out
                break;
            # for all the other tags
            else:
                # keep the thread going
                cmdQueue.put('restart')
                # want to see the tag id?
                print(msg)

    # wait for the thread to terminate
    nfcThread.join()
    # close the device
    nfc_close(pnd)
    # release the context
    nfc_exit(context)
