include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-pushbot
PKG_VERSION:=3.8.10
PKG_RELEASE:=1

PKG_MAINTAINER:=tty228 <tty228@yeah.net>  zzsj0928

LUCI_TITLE:=LuCI support for Pushbot
LUCI_PKGARCH:=all
LUCI_DEPENDS:=+iputils-arping +curl +jq +aes-tool


define Package/$(PKG_NAME)/install
    $(INSTALL_DIR) $(1)/etc/init.d
    $(INSTALL_DIR) $(1)/usr/bin
    $(INSTALL_BIN) $(PKG_BUILD_DIR)/root/usr/bin/pushbot/pushbot  $(1)/usr/bin/pushbot/pushbot
    $(INSTALL_BIN) $(PKG_BUILD_DIR)/root/etc/init.d/pushbot  $(1)/etc/init.d/pushbot
endef

define Package/$(PKG_NAME)/conffiles
/etc/config/pushbot
/usr/bin/pushbot/api/diy.json
/usr/bin/pushbot/api/ipv4.list
/usr/bin/pushbot/api/ipv6.list
endef

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt buildroot signature
