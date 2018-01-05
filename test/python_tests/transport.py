# -*- coding: utf-8 -*-

# this file is under GNU General Public License 3.0
# Copyleft 2017, p≡p foundation


"""
This module is implementing a basic message transport. Messages are written
into the artificial home of the receiver and deleted when read.
"""


import os
import time
from glob import glob


def send_message(to, msg):
    "send message by creating a file in recipient's artificial home"

    recipient_dir = os.path.join(os.pardir, to)
    filename = '{:024x}'.format(int(time.monotonic() * 10000000000)) + \
            os.extsep + "eml"
    dotpath = os.path.join(recipient_dir, "." + filename)
    path = os.path.join(recipient_dir, filename)

    with open(dotpath, "w") as file:
        file.write(msg)
    
    os.rename(dotpath, path)


def recv_message():
    """receive message by returning the first .eml files content in artificial
    home"""

    filename = glob("*.eml")[0]

    with open(filename, "r") as file:
        msg = file.read()

    os.remove(filename)

    return msg


def wait_for_message():
    "wait until a message arrives and return the message"

    while True:
        try:
            msg = recv_message()
        except IndexError:
            time.sleep(1)
        else:
            break

    return msg

