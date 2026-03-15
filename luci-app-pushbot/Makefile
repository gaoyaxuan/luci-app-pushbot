include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-pushbot
PKG_VERSION:=3.8.16
PKG_RELEASE:=1

PKG_MAINTAINER:=tty228 <tty228@yeah.net>  zzsj0928

LUCI_TITLE:=LuCI support for Pushbot
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+bash +iputils-arping +curl +jq +smartmontools \
	+LUCI_APP_PUSHBOT_ENABLE_AES_TOOL:aes-tool

define Package/$(PKG_NAME)/config
	config LUCI_APP_PUSHBOT_ENABLE_AES_TOOL
		bool "Include aes-tool (required for Bark GCM encryption)"
		default n
		help
		  Install aes-tool for AES-GCM encryption support in Bark push.
		  CBC/ECB encryption uses system openssl and does not need this.

	config LUCI_APP_PUSHBOT_INCLUDE_OUI_DATA
		bool "Include built-in MAC vendor database (OUI)"
		default n
		help
		  Download and embed IEEE OUI data during compilation.
		  This avoids needing to download it on the router at runtime.
		  Adds approximately 1.8MB (full) to the package size.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
ifeq ($(CONFIG_LUCI_APP_PUSHBOT_INCLUDE_OUI_DATA),y)
	$(info >>> Downloading IEEE OUI database...)
	curl -sS --retry 3 -m 120 -o $(PKG_BUILD_DIR)/oui_raw.txt \
		https://standards-oui.ieee.org/oui/oui.txt || \
		{ echo "ERROR: Failed to download OUI database"; exit 1; }
	grep "base 16" $(PKG_BUILD_DIR)/oui_raw.txt > $(PKG_BUILD_DIR)/oui_base.txt
	rm -f $(PKG_BUILD_DIR)/oui_raw.txt
	@echo ">>> OUI database: $$(wc -l < $(PKG_BUILD_DIR)/oui_base.txt) entries"
endif
endef


define Package/$(PKG_NAME)/install
    $(INSTALL_DIR) $(1)/etc/init.d
    $(INSTALL_DIR) $(1)/usr/bin
    $(INSTALL_BIN) $(PKG_BUILD_DIR)/root/usr/bin/pushbot/pushbot  $(1)/usr/bin/pushbot/pushbot
    $(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/init.d/pushbot  $(1)/etc/init.d/pushbot
ifeq ($(CONFIG_LUCI_APP_PUSHBOT_INCLUDE_OUI_DATA),y)
    $(INSTALL_DIR) $(1)/usr/bin/pushbot
    $(INSTALL_DATA) $(PKG_BUILD_DIR)/oui_base.txt $(1)/usr/bin/pushbot/oui_base.txt
endif
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/pushbot
/usr/bin/pushbot/api/diy.json
/usr/bin/pushbot/api/ipv4.list
/usr/bin/pushbot/api/ipv6.list
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
