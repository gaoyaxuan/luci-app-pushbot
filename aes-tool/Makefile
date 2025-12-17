include $(TOPDIR)/rules.mk

PKG_NAME:=aes-tool
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/aes-tool
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=AES encryption tool with Base64 output
  DEPENDS:=
endef

define Package/aes-tool/description
  Lightweight AES encryption tool.
  Supports CBC/ECB/CTR modes with AES-128/192/256.
  Outputs Base64 encoded ciphertext.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_LDFLAGS) \
		-o $(PKG_BUILD_DIR)/aes-tool \
		$(PKG_BUILD_DIR)/aes.c \
		$(PKG_BUILD_DIR)/main.c \
		-DAES256=1 -DCBC=1 -DECB=1 -DCTR=1
endef

define Package/aes-tool/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/aes-tool $(1)/usr/bin/
endef

$(eval $(call BuildPackage,aes-tool))
