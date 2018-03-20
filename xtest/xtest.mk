################################################################################
#
# xtest
#
################################################################################

XTEST_VERSION = 1.0
XTEST_SITE = $(BR2_EXTERNAL_MIPS_REE_PATH)/package/mips-tee-test/xtest
XTEST_SITE_METHOD = local
XTEST_INSTALL_STAGING = YES
XTEST_INSTALL_TARGET = YES
XTEST_BUILD_DIR = $(BUILD_DIR)/xtest-$(LIBTEEC_VERSION)
XTEST_TEE_DIR = $(BR2_EXTERNAL_MIPS_REE_PATH)/../tee/mips-lk/app/xtest

ifeq ($(BR2_PACKAGE_XTEST_GP), y)
define XTEST_GENERATE_GP_TESTS
	$(@D)/scripts/do-generate_gp_tests $(@D)
endef

define XTEST_PATCH_TEST_CASES
	patch -d $(BUILD_DIR) -N -p0 < $(@D)/patches/0001-xtest-rules_generated.patch
	patch -d $(BUILD_DIR) -N -p0 < $(@D)/patches/0002-xtest_70000.c-fix.patch
	patch -d $(BUILD_DIR) -N -p0 < $(@D)/patches/0003-additional_tests.patch
	patch -d $(BUILD_DIR) -N -p0 < $(@D)/patches/0004-xtest_70000.c-threads.patch
	patch -d $(BUILD_DIR) -N -p0 < $(@D)/patches/xtest_75000_missing_cmd_id.patch
endef

XTEST_POST_RSYNC_HOOKS += XTEST_GENERATE_GP_TESTS
XTEST_POST_RSYNC_HOOKS += XTEST_PATCH_TEST_CASES
endif

define XTEST_BUILD_CMDS
	$(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D) all
endef

define XTEST_INSTALL_TARGET_CMDS
	cp $(XTEST_BUILD_DIR)/xtest $(TARGET_DIR)/usr/bin
endef

xtest-clean:
	rm -rf $(XTEST_BUILD_DIR) $(XTEST_TEE_DIR)

xtest-rebuild: xtest-clean

$(eval $(generic-package))
