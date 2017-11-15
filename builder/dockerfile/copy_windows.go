package dockerfile

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/system"
	"golang.org/x/sys/windows"
)

var pathBlacklist = map[string]bool{
	"c:\\":        true,
	"c:\\windows": true,
}

func fixPermissions(source, destination string, identity idtools.Identity, overrideSkip bool) error {

	if identity.IdType == idtools.TypeIDSID {
		var sid *windows.SID

		privileges := []string{winio.SeRestorePrivilege, winio.SeTakeOwnershipPrivilege}

		err := winio.EnableProcessPrivileges(privileges)
		if err != nil {
			return err
		}

		defer winio.DisableProcessPrivileges(privileges)

		sid, err = windows.StringToSid(identity.IdSid)
		if err != nil {
			return err

		}

		// Owners on *nix have read/write/delete/read control and write DAC.
		// Add an ACE that grants this to the user/group specified with the
		// chown option.

		sddlString := system.SddlAdministratorsLocalSystem
		sddlString += "(A;OICI;GRGWRCWDSD;;;" + identity.IdSid + ")"

		securityDescriptor, err := winio.SddlToSecurityDescriptor(sddlString)
		if err != nil {
			return err
		}

		var daclPresent uint32
		var daclDefaulted uint32
		var dacl *byte

		err = system.GetSecurityDescriptorDacl(&securityDescriptor[0], &daclPresent, &dacl, &daclDefaulted)
		if err != nil {
			return err
		}

		err = system.SetNamedSecurityInfo(windows.StringToUTF16Ptr(destination), system.SE_FILE_OBJECT, system.OWNER_SECURITY_INFORMATION|system.DACL_SECURITY_INFORMATION, sid, nil, dacl, nil)
		if err != nil {
			return err
		}

		return err
	}

	return nil
}

func validateCopySourcePath(imageSource *imageMount, origPath, platform string) error {
	// validate windows paths from other images + LCOW
	if imageSource == nil || platform != "windows" {
		return nil
	}

	origPath = filepath.FromSlash(origPath)
	p := strings.ToLower(filepath.Clean(origPath))
	if !filepath.IsAbs(p) {
		if filepath.VolumeName(p) != "" {
			if p[len(p)-2:] == ":." { // case where clean returns weird c:. paths
				p = p[:len(p)-1]
			}
			p += "\\"
		} else {
			p = filepath.Join("c:\\", p)
		}
	}
	if _, blacklisted := pathBlacklist[p]; blacklisted {
		return errors.New("copy from c:\\ or c:\\windows is not allowed on windows")
	}
	return nil
}
