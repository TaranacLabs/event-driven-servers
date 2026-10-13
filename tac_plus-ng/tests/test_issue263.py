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


"""#263: the TACACS+ MS-CHAP path crashed the worker on a NULL pointer.

1. MS-CHAPv1, a user with a local "password ms-chap = clear": a *successful*
   login stored through the NULL nt_hash_set that do_mschap() passes
   (authen.c mschap_helper(), since 3ad4f8a). A wrong password failed normally.
2. MS-CHAPv2: do_mschapv2() hashed session->mschap.nt_response, still NULL, as
   the peer challenge (since b4b1b86), before the user was even looked up. Any
   MS-CHAPv2 START from a client that knows the device key crashed the worker,
   whatever the user name or password.

A worker crash is invisible to the next client (spawnd starts a new worker),
so each test runs on a daemon of its own and checks the crash detectors
(tactest/detect.py) itself: expectedFailure does not cover a failure in a
cleanup. Needs a build with OpenSSL (MS-CHAP is WITH_CRYPTO only).
"""

import unittest

from tactest import DaemonTestCase, detect, features, tacacs

CONFIG = """
	device single {
		address = 127.0.0.3
		key = tactest
		single-connection = yes
	}
	user alice {
		password ms-chap = clear alicepw
	}
	ruleset {
		rule { script { permit } }
	}
"""


@unittest.skipUnless("openssl" in features(), "MS-CHAP needs a build with OpenSSL")
class MsChapCrash(DaemonTestCase):
    CONFIG = None

    def login(self, version, password, user="alice"):
        d = self.start_daemon(CONFIG, check=False)
        base = detect.Baseline(d)
        with d.connect() as c:
            try:
                status = c.mschap(user, password, version=version).status_name
            except (tacacs.Closed, tacacs.ProtocolError) as e:
                status = "no reply: %s" % e
        return status, base.check()

    def test_issue263_mschap_v1_success(self):
        """The login the crash needed: correct password of a local cleartext user."""
        self.assertEqual(self.login(1, "alicepw"), ("PASS", []))

    def test_issue263_mschap_v1_wrong_password(self):
        """A wrong password never reached the store; it failed normally even on master."""
        self.assertEqual(self.login(1, "wrong"), ("FAIL", []))

    def test_issue263_mschap_v2_success(self):
        self.assertEqual(self.login(2, "alicepw"), ("PASS", []))

    def test_issue263_mschap_v2_unknown_user_is_a_plain_reject(self):
        """The v2 crash fired before the user lookup; an unknown user must just fail now."""
        self.assertEqual(self.login(2, "whatever", user="ghost"), ("FAIL", []))


if __name__ == "__main__":
    unittest.main()
