# See LICENSE for licensing information.

PROJECT = gun

# Options.

CT_OPTS += -pa test -ct_hooks gun_ct_hook [] -boot start_sasl
PLT_APPS = ssl

# Dependencies.

DEPS = cowlib ranch
dep_cowlib = git https://github.com/ninenines/cowlib 1.3.0

TEST_DEPS = ct_helper
dep_ct_helper = git https://github.com/extend/ct_helper.git master

# Standard targets.

include erlang.mk

# AsciiDoc.

asciidoc:
	a2x -v -f pdf doc/src/guide/book.asciidoc && mv doc/src/guide/book.pdf doc/guide.pdf
	a2x -v -f chunked doc/src/guide/book.asciidoc && mv doc/src/guide/book.chunked/* doc/
	rmdir doc/src/guide/book.chunked

clean::
	$(gen_verbose) rm doc/guide.pdf doc/*.html doc/*.css
