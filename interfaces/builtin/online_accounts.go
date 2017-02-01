// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2017 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package builtin

import (
	"github.com/snapcore/snapd/interfaces"
)

var onlineAccountsPermanentSlotAppArmor = []byte(`
# Description: Allow operating as the Online Accounts service. Reserved because
# this gives privileged access to the system.
# Usage: reserved

# DBus accesses
#include <abstractions/dbus-session-strict>

dbus (send)
    bus=session
    path=/org/freedesktop/DBus
    interface=org.freedesktop.DBus
    member={RequestName,ReleaseName,GetConnectionCredentials}
    peer=(name=org.freedesktop.DBus),
`)

var onlineAccountsConnectedPlugAppArmor = []byte(`
# Description: Allow using Online Accounts service. Common because the access
# to user data is actually mediated by the Online Accounts service itself.
# Usage: common

#include <abstractions/dbus-session-strict>

# Online Accounts v2 API
dbus (receive, send)
    bus=session
    interface=com.ubuntu.OnlineAccounts.Manager
    peer=(label=###SLOT_SECURITY_TAGS###),
`)

var onlineAccountsPermanentSlotSecComp = []byte(`
getsockname
recvmsg
sendmsg
sendto
`)

var onlineAccountsConnectedPlugSecComp = []byte(`
getsockname
recvmsg
sendmsg
sendto
`)

var onlineAccountsPermanentSlotDBus = []byte(`
<policy user="default">
    <allow own="com.ubuntu.OnlineAccounts.Manager"/>
    <allow send_destination="com.ubuntu.OnlineAccounts.Manager"/>
    <allow send_interface="com.ubuntu.OnlineAccounts.Manager"/>
</policy>
`)

var onlineAccountsConnectedPlugDBus = []byte(`
<policy context="default">
    <deny own="com.ubuntu.OnlineAccounts.Manager"/>
    <allow send_destination="com.ubuntu.OnlineAccounts.Manager"/>
    <allow send_interface="com.ubuntu.OnlineAccounts.Manager"/>
</policy>
`)

type OnlineAccountsInterface struct{}

func (iface *OnlineAccountsInterface) Name() string {
	return "online-accounts"
}

func (iface *OnlineAccountsInterface) PermanentPlugSnippet(plug *interfaces.Plug, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityDBus, interfaces.SecurityAppArmor, interfaces.SecuritySecComp, interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, nil
	}
}

func (iface *OnlineAccountsInterface) ConnectedPlugSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		return onlineAccountsConnectedPlugAppArmor, nil
	case interfaces.SecurityDBus:
		return onlineAccountsConnectedPlugDBus, nil
	case interfaces.SecuritySecComp:
		return onlineAccountsConnectedPlugSecComp, nil
	case interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, nil
	}
}

func (iface *OnlineAccountsInterface) ConnectedSlotSnippet(plug *interfaces.Plug, slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	return nil, nil
}

func (iface *OnlineAccountsInterface) PermanentSlotSnippet(slot *interfaces.Slot, securitySystem interfaces.SecuritySystem) ([]byte, error) {
	switch securitySystem {
	case interfaces.SecurityAppArmor:
		return onlineAccountsPermanentSlotAppArmor, nil
	case interfaces.SecurityDBus:
		return onlineAccountsPermanentSlotDBus, nil
	case interfaces.SecuritySecComp:
		return onlineAccountsPermanentSlotSecComp, nil
	case interfaces.SecurityUDev, interfaces.SecurityMount:
		return nil, nil
	default:
		return nil, nil
	}
}

func (iface *OnlineAccountsInterface) SanitizePlug(plug *interfaces.Plug) error {
	return nil
}

func (iface *OnlineAccountsInterface) SanitizeSlot(slot *interfaces.Slot) error {
	return nil
}

func (iface *OnlineAccountsInterface) AutoConnect(plug *interfaces.Plug, slot *interfaces.Slot) bool {
	return false // FIXME tmp to test interface hooks
}
