# See LICENSE for licensing information.

PROJECT = gun

# Options.

CT_SUITES = twitter ws
CT_OPTS += -pa test -ct_hooks gun_ct_hook [] -boot start_sasl

PLT_APPS = ssl

# Dependencies.

DEPS = cowlib ranch
dep_cowlib = git https://github.com/ninenines/cowlib 1.3.0

TEST_DEPS = ct_helper
dep_ct_helper = git https://github.com/extend/ct_helper.git master

# Standard targets.

include erlang.mk
