# Copyright (C) 2026 TaranacLabs
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL ITS AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


"""Two robustness problems in the external MAVIS path, each a reply the client
never gets.

(1) A NUL byte in an answer: the daemon reads the reply as a C string
    (av_char_to_array()), so the attribute with the NUL and everything after
    it -- including the request type -- are dropped, and no reply is sent.
    mavis.py now strips the NUL, as the Perl backends do (#58).
(2) A backend that answers one request twice: the stale answer arrives while
    the child is on the next request; the daemon killed the child "out of
    sync" and lost that request. It now hands the request to a new child, as
    for a child that dies before answering (#228).
"""

import time
import unittest

from tactest import DaemonTestCase, Stub, detect

BACKEND = """
	user backend = mavis
	login backend = mavis
	pap backend = mavis
"""

PERMIT = """
	ruleset {
		rule { script { permit } }
	}
"""


class MessageWithNul(DaemonTestCase):
    CONFIG = None

    def test_failure_with_a_nul_in_the_message(self):
        """A failed authentication whose user response holds a NUL now reaches the client as FAIL."""
        d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + PERMIT, check=False)
        base = detect.Baseline(d)
        Stub(d).set(users={"alice": {"password": "pw"}}, message="AcceptSecurityContext error\x00, data 52e")
        with d.connect(timeout=4) as c:
            try:
                status = c.pap("alice", "wrong").status_name
            except TimeoutError as e:
                status = str(e)
        self.assertEqual((status, base.check()), ("FAIL", []))


class DoubleAnswer(DaemonTestCase):
    CONFIG = None

    def test_request_after_a_double_answer(self):
        """A backend that answered one request twice no longer loses the next request."""
        d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + PERMIT, check=False)
        base = detect.Baseline(d)
        stub = Stub(d)
        stub.set(users={"alice": {"password": "pw"}}, double_write=0.2)
        with d.connect() as c:
            self.assertEqual(c.pap("alice", "pw").status_name, "PASS")
        stub.set(users={"alice": {"password": "pw"}})
        deadline = time.monotonic() + 5
        while stub.requests()[-1]["result"] != "again" and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(stub.requests()[-1]["result"], "again")
        with d.connect(timeout=4) as c:
            try:
                status = c.pap("alice", "pw").status_name
            except TimeoutError as e:
                status = str(e)
        base.forget(stub.requests()[0]["pid"])
        self.assertEqual((status, base.check()), ("PASS", []))


if __name__ == "__main__":
    unittest.main()
