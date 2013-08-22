# See LICENSE for licensing information.

PROJECT = gun

# Options.

CT_SUITES = twitter
PLT_APPS = ssl

# Dependencies.

DEPS = cowlib ranch
dep_cowlib = pkg://cowlib master
dep_ranch = pkg://ranch master

# Standard targets.

include erlang.mk
