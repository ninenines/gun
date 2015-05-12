# See LICENSE for licensing information.

PROJECT = gun

# Options.

CT_OPTS += -pa test -ct_hooks gun_ct_hook [] -boot start_sasl
PLT_APPS = ssl
CI_OTP = OTP-17.0.2 OTP-17.1.2 OTP-17.2.2 OTP-17.3.4 OTP-17.4.1 OTP-17.5.3

CT_SUITES = twitter

# Dependencies.

DEPS = cowlib ranch
dep_cowlib = git https://github.com/ninenines/cowlib 1.3.0

TEST_DEPS = ct_helper
dep_ct_helper = git https://github.com/extend/ct_helper.git master

# Standard targets.

include erlang.mk

# Open logs after CI ends.

ci::
	xdg-open logs/all_runs.html
