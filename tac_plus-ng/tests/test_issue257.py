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


"""#257: the profile cache of a single-connection link served one user's verdict to the next.

The cache on the connection is keyed by the tac_user pointer. With MAVIS
users and "mavis cache timeout = 0" the user is freed when the session
ends, the next user may get the same address, and the cache answered with
the first user's verdict and profile. Whether the address is reused
depends on the allocator: musl reuses it on the second session, glibc
after a few, hence the users take turns several times.
"""

import os
import shutil
import sys
import tempfile
import unittest

from tactest import DaemonTestCase, prefix

ROUNDS = 6
ALLOWED = ("PASS", "PASS_ADD", ["priv-lvl=15"])
DENIED = ("FAIL", "FAIL", [])

# A MAVIS backend: both users have the password "pw", each in its own group.
STUB = r'''
import sys
sys.path.insert(0, sys.argv[1])
from mavis import (AV_A_PASSWORD, AV_A_TACTYPE, AV_A_USER, AV_V_RESULT_FAIL, AV_V_RESULT_NOTFOUND,
                   AV_V_RESULT_OK, MAVIS_DOWN, MAVIS_FINAL, Mavis)

GROUPS = {"alice": "member_alice", "bobby": "member_bobby"}

while True:
    d = Mavis()
    if not d.is_tacplus() or not d.valid():
        continue
    user, tactype = d.av_pairs.get(AV_A_USER, ""), d.av_pairs.get(AV_A_TACTYPE, "")
    if user not in GROUPS or tactype not in ("INFO", "AUTH"):
        d.write(MAVIS_DOWN, AV_V_RESULT_NOTFOUND, None)
    elif tactype == "AUTH" and d.av_pairs.get(AV_A_PASSWORD, "") != "pw":
        d.write(MAVIS_FINAL, AV_V_RESULT_FAIL, "Authentication failed")
    else:
        d.set_tacmember(GROUPS[user])
        d.write(MAVIS_FINAL, AV_V_RESULT_OK, None)
'''

POLICY = """
	mavis module = external {
		exec = %(python)s %(python)s -u %(stub)s %(mavis_py)s
		childs min = 1
		childs max = 1
	}
	user backend = mavis
	login backend = mavis
	pap backend = mavis
	device world {
		address = 127.0.0.9
		key = tactest
		single-connection = yes
	}
	profile admin {
		script {
			if (service == shell) {
				set priv-lvl = 15
				permit
			}
		}
	}
	group member_alice { }
	group member_bobby { }
	ruleset {
		rule allow_alice {
			script { if (member == member_alice) { profile = admin permit } }
		}
		rule deny_bobby {
			script { if (member == member_bobby) { deny } }
		}
	}
"""


class ProfileCache(DaemonTestCase):
    CONFIG = None

    def setUp(self):
        super().setUp()
        tmp = tempfile.mkdtemp(prefix="tactest-stub-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        stub = os.path.join(tmp, "mavis_stub.py")
        with open(stub, "w") as f:
            f.write(STUB)
        mavis_py = os.path.join(prefix(), "lib", "mavis")
        self.daemon = self.start_daemon(POLICY % dict(python=sys.executable, stub=stub, mavis_py=mavis_py))

    def connect_world(self):
        return self.connect(source="127.0.0.9", single_connect=True, daemon=self.daemon)

    @staticmethod
    def session(c, user, login):
        status = login(user, "pw").status_name
        author = c.author(user, ["service=shell", "cmd="])
        return status, author.status_name, author.args

    def test_issue257_users_take_turns_on_one_connection(self):
        c = self.connect_world()
        for login in (c.ascii_login, c.pap):
            for i in range(ROUNDS):
                with self.subTest(login=login.__name__, round=i):
                    self.assertEqual(self.session(c, "alice", login), ALLOWED)
                    self.assertEqual(self.session(c, "bobby", login), DENIED)

    def test_issue257_separate_connections(self):
        """The control: without a shared connection there is no cache to hit."""
        for i in range(2):
            for user, expected in (("alice", ALLOWED), ("bobby", DENIED)):
                c = self.connect_world()
                self.assertEqual(self.session(c, user, c.ascii_login), expected)


if __name__ == "__main__":
    unittest.main()
