package dockerfile

// internals for handling commands. Covers many areas and a lot of
// non-contiguous functionality. Please read the comments.

import (
	"os"
	"path/filepath"
	"strconv"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"github.com/docker/docker/pkg/fileutils"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/pkg/symlink"
	"github.com/docker/docker/pkg/system"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

func getAccountIdentity(accountName string, ctrRootPath string) (idtools.Identity, error) {

	sid, _, accType, err := windows.LookupSID("", accountName)

	if err == nil && (accType == windows.SidTypeAlias || accType == windows.SidTypeWellKnownGroup) {
		accountSid, err := sid.String()

		if err != nil {
			return idtools.Identity{IdType: idtools.TypeIDSID, IdSid: ""}, errors.Wrapf(err, "error converting SID to string")
		}

		return idtools.Identity{IdType: idtools.TypeIDSID, IdSid: accountSid}, nil
	}

	if accountName == "ContainerAdministrator" {
		return idtools.Identity{IdType: idtools.TypeIDSID, IdSid: "S-1-5-93-2-1"}, nil

	} else if accountName == "ContainerUser" {
		return idtools.Identity{IdType: idtools.TypeIDSID, IdSid: "S-1-5-93-2-2"}, nil
	}

	// This will be present on Windows
	_, err = os.Stat(filepath.Join(ctrRootPath, "Windows"))
	if err != nil {
		return idtools.Identity{IdType: idtools.TypeIDSID, IdSid: ""}, errors.Wrapf(err, "can't resolve \\Windows path in container")
	}

	samDatabasePath, err := symlink.FollowSymlinkInScope(filepath.Join(ctrRootPath, "Windows", "system32", "config", "SAM"), ctrRootPath)
	if err != nil {
		return idtools.Identity{IdType: idtools.TypeIDPair, IdPair: idtools.IDPair{}}, errors.Wrapf(err, "can't resolve SAM database path in container")
	}

	accountSid, err := lookupNTAccount(accountName, samDatabasePath)

	var identity idtools.Identity

	identity.IdType = idtools.TypeIDSID
	identity.IdSid = accountSid

	return identity, err
}

func lookupNTAccount(accountName string, samDatabasePath string) (string, error) {

	tempDirectory, err := ioutils.TempDir("", "SAMDB-")
	if err != nil {
		return "", err
	}

	defer os.RemoveAll(tempDirectory)

	samDatabase := tempDirectory + "\\SAM"

	_, err = fileutils.CopyFile(samDatabasePath, samDatabase)
	if err != nil {
		return "", err
	}

	var samKey windows.Handle
	var innerSamKey windows.Handle
	var domainsKey windows.Handle
	var accountKey windows.Handle
	var usersKey windows.Handle
	var groupsKey windows.Handle
	var userNamesKey windows.Handle
	var groupNamesKey windows.Handle

	_, mountName := filepath.Split(tempDirectory)

	privileges := []string{winio.SeBackupPrivilege, winio.SeRestorePrivilege}

	err = winio.EnableProcessPrivileges(privileges)
	if err != nil {
		return "", err
	}

	defer winio.DisableProcessPrivileges(privileges)

	err = system.RegLoadKey(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(mountName), windows.StringToUTF16Ptr(samDatabase))
	if err != nil {
		return "", err
	}

	defer system.RegUnLoadKey(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(mountName))

	err = windows.RegOpenKeyEx(windows.HKEY_LOCAL_MACHINE, windows.StringToUTF16Ptr(mountName), 0, windows.KEY_READ, &samKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(samKey)

	err = changeKeySecurity(samKey, "SAM")
	if err != nil {
		return "", err
	}

	err = windows.RegOpenKeyEx(samKey, windows.StringToUTF16Ptr("SAM"), 0, windows.KEY_READ, &innerSamKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(innerSamKey)

	err = changeKeySecurity(innerSamKey, "Domains")
	if err != nil {
		return "", err
	}

	err = windows.RegOpenKeyEx(innerSamKey, windows.StringToUTF16Ptr("Domains"), 0, windows.KEY_READ, &domainsKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(domainsKey)

	err = changeKeySecurity(domainsKey, "Account")
	if err != nil {
		return "", err
	}

	err = windows.RegOpenKeyEx(domainsKey, windows.StringToUTF16Ptr("Account"), 0, windows.KEY_READ, &accountKey)
	if err != nil {
		return "", err
	}

	computerSid, err := getComputerSid(accountKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(accountKey)

	err = changeKeySecurity(accountKey, "Users")
	if err != nil {
		return "", err
	}

	err = windows.RegOpenKeyEx(accountKey, windows.StringToUTF16Ptr("Users"), 0, windows.KEY_READ, &usersKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(usersKey)

	err = changeKeySecurity(accountKey, "Groups")
	if err != nil {
		return "", err
	}

	err = windows.RegOpenKeyEx(accountKey, windows.StringToUTF16Ptr("Groups"), 0, windows.KEY_READ, &groupsKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(groupsKey)

	err = changeKeySecurity(usersKey, "Names")
	if err != nil {
		return "", err
	}

	err = changeKeySecurity(groupsKey, "Names")
	if err != nil {
		return "", err
	}

	err = windows.RegOpenKeyEx(usersKey, windows.StringToUTF16Ptr("Names"), 0, windows.KEY_READ, &userNamesKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(userNamesKey)

	userSid, locatedUserAccount, err := lookupNTUser(userNamesKey, accountName, computerSid)
	if locatedUserAccount != false {
		return userSid, nil
	}

	err = windows.RegOpenKeyEx(groupsKey, windows.StringToUTF16Ptr("Names"), 0, windows.KEY_READ, &groupNamesKey)
	if err != nil {
		return "", err
	}

	defer windows.RegCloseKey(groupNamesKey)

	groupSid, locatedGroupAccount, err := lookupNTGroup(groupNamesKey, accountName, computerSid)
	if locatedGroupAccount != false {
		return groupSid, nil
	}

	return "", system.ERROR_NO_SUCH_USER
}

func lookupNTUser(userNamesKey windows.Handle, userStr string, computerSid string) (string, bool, error) {

	var subKeyCount uint32
	var maxSubKeyLen uint32
	var accountName string

	err := windows.RegQueryInfoKey(userNamesKey, nil, nil, nil, &subKeyCount, &maxSubKeyLen, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return "", false, err
	}

	accountLocated := false
	accountBuffer := make([]uint16, maxSubKeyLen+1)
	maximumAccountBufferLength := uint32(len(accountBuffer))
	accountBufferLength := maximumAccountBufferLength
	accountSid := ""

	for index := uint32(0); index < subKeyCount; index++ {
		accountBufferLength = maximumAccountBufferLength
		err := windows.RegEnumKeyEx(userNamesKey, index, &accountBuffer[0], &accountBufferLength, nil, nil, nil, nil)

		if err != nil {
			return "", false, err
		}

		accountName = windows.UTF16ToString(accountBuffer[:])

		err = changeKeySecurity(userNamesKey, accountName)
		if err != nil {
			return "", false, err
		}

		if accountName == userStr {
			accountLocated = true
			break
		}
	}

	if accountLocated {
		var accountKey windows.Handle

		err := windows.RegOpenKeyEx(userNamesKey, &accountBuffer[0], 0, windows.KEY_READ, &accountKey)
		if err != nil {
			return "", false, err
		}

		var userRid uint32

		err = windows.RegQueryValueEx(accountKey, nil, nil, &userRid, nil, nil)
		if err != nil {
			return "", false, err
		}

		accountSid = computerSid + "-" + strconv.FormatUint(uint64(userRid), 10)

		defer windows.RegCloseKey(accountKey)
	}

	return accountSid, accountLocated, nil
}

func lookupNTGroup(groupNamesKey windows.Handle, groupStr string, computerSid string) (string, bool, error) {

	var subKeyCount uint32
	var maxSubKeyLen uint32
	var accountName string

	err := windows.RegQueryInfoKey(groupNamesKey, nil, nil, nil, &subKeyCount, &maxSubKeyLen, nil, nil, nil, nil, nil, nil)
	if err != nil {
		return "", false, err
	}

	accountLocated := false
	accountBuffer := make([]uint16, maxSubKeyLen+1)
	maximumAccountBufferLength := uint32(len(accountBuffer))
	accountBufferLength := maximumAccountBufferLength
	accountSid := ""

	for index := uint32(0); index < subKeyCount; index++ {
		accountBufferLength = maximumAccountBufferLength
		err := windows.RegEnumKeyEx(groupNamesKey, index, &accountBuffer[0], &accountBufferLength, nil, nil, nil, nil)

		if err != nil {
			return "", false, err
		}

		accountName = windows.UTF16ToString(accountBuffer[:])

		err = changeKeySecurity(groupNamesKey, accountName)
		if err != nil {
			return "", false, err
		}

		if accountName == groupStr {
			accountLocated = true
			break
		}
	}

	if accountLocated {
		var accountKey windows.Handle

		err := windows.RegOpenKeyEx(groupNamesKey, &accountBuffer[0], 0, windows.KEY_READ, &accountKey)
		if err != nil {
			return "", false, err
		}

		var groupRid uint32

		err = windows.RegQueryValueEx(accountKey, nil, nil, &groupRid, nil, nil)
		if err != nil {
			return "", false, err
		}

		accountSid = computerSid + "-" + strconv.FormatUint(uint64(groupRid), 10)

		defer windows.RegCloseKey(accountKey)
	}

	return accountSid, accountLocated, nil
}

func changeKeySecurity(rootKey windows.Handle, subkey string) error {
	var innerKey windows.Handle

	err := windows.RegOpenKeyEx(rootKey, windows.StringToUTF16Ptr(subkey), 0, system.READ_CONTROL|system.WRITE_DAC, &innerKey)
	if err != nil {
		return err
	}

	defer windows.RegCloseKey(innerKey)

	securityDescriptor, err := winio.SddlToSecurityDescriptor("D:PARAI(A;CIOI;KA;;;BA)(A;CIOI;KA;;;SY)")
	if err != nil {
		return err
	}

	err = system.RegSetKeySecurity(innerKey, system.DACL_SECURITY_INFORMATION, &securityDescriptor[0])
	if err != nil {
		return err
	}

	return nil
}

func getComputerSid(accountKey windows.Handle) (string, error) {

	var dataLength uint32
	var valueType uint32
	var dataBuffer []byte

	dataLength = 0

	err := windows.RegQueryValueEx(accountKey, windows.StringToUTF16Ptr("V"), nil, &valueType, nil, &dataLength)
	if err != nil {
		return "", err
	}

	if valueType != windows.REG_BINARY {
		return "", system.ERROR_UNSUPPORTED_TYPE
	}

	dataBuffer = make([]byte, dataLength)

	err = windows.RegQueryValueEx(accountKey, windows.StringToUTF16Ptr("V"), nil, &valueType, (*byte)(unsafe.Pointer(&dataBuffer[0])), &dataLength)
	if err != nil {
		return "", err
	}

	firstSubAuthority := *(*uint32)(unsafe.Pointer(&dataBuffer[dataLength-12]))
	secondSubAuthority := *(*uint32)(unsafe.Pointer(&dataBuffer[dataLength-8]))
	thirdSubAuthority := *(*uint32)(unsafe.Pointer(&dataBuffer[dataLength-4]))

	computerSid := "S-1-5-21-" + strconv.FormatUint(uint64(firstSubAuthority), 10) + "-" + strconv.FormatUint(uint64(secondSubAuthority), 10) + "-" + strconv.FormatUint(uint64(thirdSubAuthority), 10)

	return computerSid, nil
}
