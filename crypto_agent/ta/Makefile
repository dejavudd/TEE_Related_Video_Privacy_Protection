CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
BINARY = 24029442-44cd-4960-b4d3-33f7ec14b649

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: 

clean: clean_ta_file
.PHONY: clean_ta_file
clean_ta_file:
	rm -f $(BINARY).ta
