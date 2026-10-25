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



"""The connection log says why the packets of a connection were refused.

tac_read() refuses a packet that no key of the device decodes (the length
fields don't add up after deobfuscation) and a packet whose obfuscation
breaks RFC 8907 4.5 / RFC 9887: TAC_PLUS_UNENCRYPTED_FLAG over plain TCP,
no flag over TLS. The reason reached syslog at most ("Illegal packet" for
authentication, nothing for authorization and accounting), and the
CONN-STOP record of the connection log was the same as for a connection
that was served: ${hint} empty.

${hint} of CONN-STOP is now "key mismatch" or "unobfuscated packet"
("obfuscated packet" over TLS). It stays empty while another key of the
device still decodes the packet (key rotation), and for the refusals that
have their own syslog line and nothing to do with the key: an unknown
minor or major version, a stray sequence number.
"""

import re
import time
import unittest

from tactest import LINUX, DaemonTestCase, tacacs
from test_tls import DEVICES, TLS_REALM, TlsTestCase, policy

CONNECTION_LOG = """
	log connection {
		destination = "$tmp/connection.log"
		connection format = "$${msgid}|$${hint}"
	}
	connection log = connection
"""

POLICY = CONNECTION_LOG + """
	device inv {
		address = 127.0.0.30
		key = right
	}
	device rotating {
		address = 127.0.0.31
		key = new
		key = old
	}
	user alice {
		password login = clear alicepw
		password pap = login
	}
	ruleset {
		rule { script { permit } }
	}
"""

RECORD = re.compile(r"(CONN-[A-Z]+)\|(.*)$")


class HintMixin:
    """The connection log records of what a client did on a connection of its own."""

    def records(self, client, timeout=5.0):
        """Run client(); the (msgid, hint) records the connection left, once CONN-STOP is there.

        The test waits for CONN-STOP so that it can't spill into the next test.
        """
        offset = self.daemon.log_size("connection")
        try:
            client()
        except (tacacs.Closed, tacacs.ProtocolError, TimeoutError, ConnectionError):
            pass
        deadline = time.monotonic() + timeout
        while True:
            found = [RECORD.search(line) for line in self.daemon.read_log("connection", offset).splitlines()]
            found = [m.groups() for m in found if m]
            if any(msgid == "CONN-STOP" for msgid, _ in found):
                return found
            if time.monotonic() > deadline:
                self.fail("no CONN-STOP record within %.0f s: %r" % (timeout, found))
            time.sleep(0.02)

    def stop_hint(self, client):
        found = self.records(client)
        stops = [hint for msgid, hint in found if msgid == "CONN-STOP"]
        self.assertEqual(len(stops), 1, found)
        return stops[0]


@unittest.skipUnless(LINUX, "127.0.0.0/8 local addresses")
class ConnectionLogHint(HintMixin, DaemonTestCase):
    CONFIG = POLICY

    def request(self, kind, key="right", source="127.0.0.30", **encode):
        """A client that sends one request of the given kind and reads the answer."""
        packets = {
            "authen": lambda: tacacs.Packet.authen_start(user="alice", data="alicepw",
                                                         authen_type=tacacs.AUTHEN_TYPE_PAP,
                                                         version=tacacs.VERSION_ONE),
            "author": lambda: tacacs.Packet.author_request("alice", ["service=shell", "cmd="]),
            "acct": lambda: tacacs.Packet.acct_request("alice", ["service=shell", "task_id=1"]),
        }

        def client():
            with self.connect(key=key, source=source) as c:
                c.send_raw(packets[kind]().encode(c.key, **encode))
                c.recv()
        return client

    def test_wrong_key(self):
        for kind in ("authen", "author", "acct"):
            with self.subTest(kind=kind):
                self.assertEqual(self.stop_hint(self.request(kind, key="wrong")), "key mismatch")

    def test_right_key(self):
        for kind in ("authen", "author", "acct"):
            with self.subTest(kind=kind):
                self.assertEqual(self.stop_hint(self.request(kind)), "")

    def test_served_requests_leave_the_hint_empty(self):
        def client():
            with self.connect(key="right", source="127.0.0.30") as c:
                self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(self.records(client), [("CONN-START", ""), ("CONN-STOP", "")])

    def test_unobfuscated_packet(self):
        """TAC_PLUS_UNENCRYPTED_FLAG over plain TCP: "Peers MUST use Obfuscation."."""
        for kind in ("authen", "author", "acct"):
            with self.subTest(kind=kind):
                hint = self.stop_hint(self.request(kind, flags=tacacs.FLAG_UNENCRYPTED))
                self.assertEqual(hint, "unobfuscated packet")

    def test_key_rotation(self):
        """The second key decodes the packet: no mismatch, the request is served."""
        for key in ("new", "old"):
            with self.subTest(key=key):
                def client():
                    with self.connect(key=key, source="127.0.0.31") as c:
                        self.assertTrue(c.pap("alice", "alicepw").ok)
                self.assertEqual(self.stop_hint(client), "")

    def test_key_rotation_neither_key(self):
        self.assertEqual(self.stop_hint(self.request("authen", key="other", source="127.0.0.31")), "key mismatch")

    def test_unknown_minor_version(self):
        """Refused as an "Illegal packet" as well, but the key is right."""
        for kind in ("authen", "author", "acct"):
            with self.subTest(kind=kind):
                self.assertEqual(self.stop_hint(self.request(kind, version=0xC5)), "")

    def test_unknown_major_version(self):
        def client():
            with self.connect(key="right", source="127.0.0.30") as c:
                c.send_raw(b"GET / HTTP/1.0\r\n\r\n")
                c.closed(2.0)
        self.assertEqual(self.stop_hint(client), "")

    def test_stray_sequence_number(self):
        self.assertEqual(self.stop_hint(self.request("authen", seq_no=3)), "")


class ConnectionLogHintTls(HintMixin, TlsTestCase):
    """Over TLS the packets must not be obfuscated (RFC 9887)."""

    LISTEN = {"tls": "tls = yes"}
    BODY = TLS_REALM + CONNECTION_LOG + DEVICES + policy()

    def test_obfuscated_packet(self):
        def client():
            with self.connect_tls() as c:
                pkt = tacacs.Packet.authen_start(user="alice", data="alicepw", authen_type=tacacs.AUTHEN_TYPE_PAP,
                                                 version=tacacs.VERSION_ONE)
                c.send_raw(pkt.encode("tactest"))
                c.recv()
        self.assertEqual(self.stop_hint(client), "obfuscated packet")

    def test_unobfuscated_packet_over_tls(self):
        def client():
            with self.connect_tls() as c:
                self.assertTrue(c.pap("alice", "alicepw").ok)
        self.assertEqual(self.stop_hint(client), "")


if __name__ == "__main__":
    unittest.main()
