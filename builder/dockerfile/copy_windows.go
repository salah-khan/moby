package dockerfile

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/system"
	"golang.org/x/sys/windows"
	"github.com/Microsoft/go-winio"
)

var pathBlacklist = map[string]bool{
	"c:\\":        true,
	"c:\\windows": true,
}

func fixPermissions(source, destination string, identity idtools.Identity, overrideSkip bool) error {
	
	if identity.IdType == idtools.TypeIDSID {
		var sid *windows.SID

		privileges := []string{winio.SeRestorePrivilege}

		err := winio.EnableProcessPrivileges(privileges)
		if err != nil {
			return err
		}

		defer winio.DisableProcessPrivileges(privileges)

		sid, err = windows.StringToSid(identity.IdSid)
		if err != nil {
			return err
		}

		err = system.SetNamedSecurityInfo(windows.StringToUTF16Ptr(destination), system.SE_FILE_OBJECT, system.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil)

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
