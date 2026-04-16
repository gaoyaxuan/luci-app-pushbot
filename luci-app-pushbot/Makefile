include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-pushbot
PKG_VERSION:=3.8.18
PKG_RELEASE:=1

PKG_MAINTAINER:=tty228 <tty228@yeah.net>  zzsj0928

LUCI_TITLE:=LuCI support for Pushbot
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+bash +iputils-arping +curl +jq +smartmontools \
	+LUCI_APP_PUSHBOT_ENABLE_AES_TOOL:aes-tool

PKG_CONFIG_DEPENDS:= \
	CONFIG_LUCI_APP_PUSHBOT_ENABLE_AES_TOOL \
	CONFIG_LUCI_APP_PUSHBOT_OUI_NONE \
	CONFIG_LUCI_APP_PUSHBOT_OUI_LITE \
	CONFIG_LUCI_APP_PUSHBOT_OUI_FULL

define Package/$(PKG_NAME)/config
	config LUCI_APP_PUSHBOT_ENABLE_AES_TOOL
		bool "Include aes-tool (required for Bark GCM encryption)"
		default n
		help
		  Install aes-tool for AES-GCM encryption support in Bark push.
		  CBC/ECB encryption uses system openssl and does not need this.

	choice
		prompt "Built-in MAC vendor database (OUI)"
		default LUCI_APP_PUSHBOT_OUI_NONE
		help
		  Select whether to include a pre-built MAC vendor (OUI) database.
		  This avoids needing to download it on the router at runtime.

	config LUCI_APP_PUSHBOT_OUI_NONE
		bool "None"
		help
		  Do not include OUI database. Users can download it at runtime.

	config LUCI_APP_PUSHBOT_OUI_LITE
		bool "Simplified (~250KB)"
		help
		  Include simplified OUI database with popular vendors only.

	config LUCI_APP_PUSHBOT_OUI_FULL
		bool "Full (~1.8MB)"
		help
		  Include the complete OUI database with all vendors.

	endchoice
endef

define Build/Prepare/luci-app-pushbot
	if [ "$(CONFIG_LUCI_APP_PUSHBOT_OUI_LITE)" = "y" ] || \
	   [ "$(CONFIG_LUCI_APP_PUSHBOT_OUI_FULL)" = "y" ]; then \
		echo ">>> Downloading IEEE OUI database..."; \
		curl -sS --retry 3 -m 120 -o $(PKG_BUILD_DIR)/oui_raw.txt \
			https://standards-oui.ieee.org/oui/oui.txt || \
			{ echo "ERROR: Failed to download OUI database"; exit 1; }; \
		mkdir -p $(PKG_BUILD_DIR)/root/usr/bin/pushbot; \
		if [ "$(CONFIG_LUCI_APP_PUSHBOT_OUI_LITE)" = "y" ]; then \
			grep "base 16" $(PKG_BUILD_DIR)/oui_raw.txt | \
				grep -iE "apple|aruba|asus|huawei|xiaomi|samsung|lg|htc|oneplus|oppo|meizu|cisco|hp|dell|lenovo|intel|tp-link|dlink|netgear|tenda|hiwifi|mercury|fast|ubq|h3c|vmware|belkin|buffalo|nokia" \
				> $(PKG_BUILD_DIR)/root/usr/bin/pushbot/oui_base.txt; \
			sed -i '/option oui_data/d' $(PKG_BUILD_DIR)/root/etc/config/pushbot; \
			printf '\toption oui_data '\''1'\''\n' >> $(PKG_BUILD_DIR)/root/etc/config/pushbot; \
			echo ">>> OUI database ready (simplified)"; \
		else \
			grep "base 16" $(PKG_BUILD_DIR)/oui_raw.txt \
				> $(PKG_BUILD_DIR)/root/usr/bin/pushbot/oui_base.txt; \
			sed -i '/option oui_data/d' $(PKG_BUILD_DIR)/root/etc/config/pushbot; \
			printf '\toption oui_data '\''2'\''\n' >> $(PKG_BUILD_DIR)/root/etc/config/pushbot; \
			echo ">>> OUI database ready (full)"; \
		fi; \
		rm -f $(PKG_BUILD_DIR)/oui_raw.txt; \
	else \
		sed -i '/option oui_data/d' $(PKG_BUILD_DIR)/root/etc/config/pushbot; \
	fi
endef


define Package/$(PKG_NAME)/install
    $(INSTALL_DIR) $(1)/etc/init.d
    $(INSTALL_DIR) $(1)/usr/bin/pushbot
    $(INSTALL_BIN) $(PKG_BUILD_DIR)/root/usr/bin/pushbot/pushbot  $(1)/usr/bin/pushbot/pushbot
    $(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/init.d/pushbot  $(1)/etc/init.d/pushbot
    if [ -f "$(PKG_BUILD_DIR)/root/usr/bin/pushbot/oui_base.txt" ]; then \
        $(INSTALL_DATA) $(PKG_BUILD_DIR)/root/usr/bin/pushbot/oui_base.txt $(1)/usr/bin/pushbot/oui_base.txt; \
    fi
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/pushbot
/usr/bin/pushbot/api/diy.json
/usr/bin/pushbot/api/ipv4.list
/usr/bin/pushbot/api/ipv6.list
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
