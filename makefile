#
# Lancet Advanced - PIN Tool Build Configuration
#
DEBUG := 1
PIN_ROOT := /home/secondst/Code/pin-4.2
ifdef PIN_ROOT
CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
else
CONFIG_ROOT := ../Config
endif
include $(CONFIG_ROOT)/makefile.config
include makefile.rules
include $(TOOLS_ROOT)/Config/makefile.default.rules
