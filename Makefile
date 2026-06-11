LIBDIR := lib
BUNDLE_PATH := $(CURDIR)/.gems
kramdown-rfc := env BUNDLE_GEMFILE=$(CURDIR)/Gemfile \
    BUNDLE_PATH=$(BUNDLE_PATH) bundle exec kramdown-rfc
include $(LIBDIR)/main.mk

$(LIBDIR)/main.mk:
ifneq (,$(shell grep "path *= *$(LIBDIR)" .gitmodules 2>/dev/null))
	git submodule sync
	git submodule update --init
else
ifneq (,$(wildcard $(ID_TEMPLATE_HOME)))
	ln -s "$(ID_TEMPLATE_HOME)" $(LIBDIR)
else
	git clone -q --depth 10 -b main \
	    https://github.com/martinthomson/i-d-template $(LIBDIR)
endif
endif
