# OpenWrt Makefile - 使用系统 mbedtls 库
# 最简单的方案，依赖 OpenWrt 的 libmbedtls

include $(TOPDIR)/rules.mk

PKG_NAME:=aes-tool
PKG_VERSION:=1.1.2
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/aes-tool
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=AES Encryption Tool
  DEPENDS:=+libmbedtls
endef

define Package/aes-tool/description
  AES encryption/decryption tool using system mbedtls library.
  Supports ECB, CBC, CTR, and GCM modes.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-DUSE_MBEDTLS_HEADERS \
		-o $(PKG_BUILD_DIR)/aes-tool \
		$(PKG_BUILD_DIR)/main.c \
		$(PKG_BUILD_DIR)/aes_crypto.c \
		-lmbedcrypto

	$(TARGET_CROSS)strip $(PKG_BUILD_DIR)/aes-tool
endef

define Package/aes-tool/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/aes-tool $(1)/usr/bin/
endef

$(eval $(call BuildPackage,aes-tool))