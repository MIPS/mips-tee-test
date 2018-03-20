################################################################################
#
# test_starter_ca
#
################################################################################

TEST_STARTER_CA_VERSION = 1.0
TEST_STARTER_CA_SITE = $(BR2_EXTERNAL_MIPS_REE_PATH)/package/mips-tee-test/clientapps/test_starter_ca
TEST_STARTER_CA_SITE_METHOD = local
TEST_STARTER_CA_INSTALL_STAGING = NO
TEST_STARTER_CA_INSTALL_TARGET = YES
TEST_STARTER_CA_BUILD_DIR = $(BUILD_DIR)/test_starter_ca-$(TEST_STARTER_CA_VERSION)

define TEST_STARTER_CA_BUILD_CMDS
	$(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D) all
endef

define TEST_STARTER_CA_INSTALL_TARGET_CMDS
	cp $(TEST_STARTER_CA_BUILD_DIR)/starter $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))
