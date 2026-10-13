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


"""A TACMEMBER with an unknown group and a syntax error crashed the worker.

parse_member() installed its own setjmp() on sym->env and left it pointing
into its returned frame; the next parse error longjmp()ed into that dead
frame. The "script out" of #189 produces such a list for a user without
groups, and it reaches parse_member() through the dynamic user profile the
daemon builds from an external MAVIS module's TACMEMBER.

The outcome was build dependent -- a worker SIGSEGV on optimized builds, the
user admitted instead of denied on a clang -O0 build -- so the test runs its
own daemon and checks the crash detectors (tactest/detect.py) after the login
rather than relying on a single status.
"""

import unittest

from tactest import DaemonTestCase, Stub, detect, tacacs

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


class BadGroupList(DaemonTestCase):
    CONFIG = None

    def login(self, member):
        d = self.start_daemon(Stub.module(childs=(1, 1)) + BACKEND + PERMIT, check=False)
        base = detect.Baseline(d)
        Stub(d).set(users={"alice": {"password": "pw", "member": member}})
        with d.connect() as c:
            try:
                status = c.pap("alice", "pw").status_name
            except (tacacs.Closed, tacacs.ProtocolError) as e:
                status = "no reply: %s" % e
        return status, base.check()

    def test_unknown_group_then_a_syntax_error(self):
        """An unparsable member list is a clean MAVIS-parse-error denial now, not a crash."""
        self.assertEqual(self.login(',"nosuchgroup"'), ("FAIL", []))

    def test_script_out_list_of_a_user_without_groups(self):
        """#189's "script out" for a user with no groups appends to an empty list."""
        self.assertEqual(self.login(',"no-login-profile"'), ("FAIL", []))


if __name__ == "__main__":
    unittest.main()
