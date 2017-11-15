// +build !windows

package dockerfile

import (
	"fmt"
	"io"
)

func getAccountIdentity(accountName string, ctrRootPath string, StdOut io.Writer) (idtools.Identity, error) {
	// This won't be called for non-Windows, but needs to be present since
	// Windows has this function for obtaining NT account information.
	return idtools.Identity{IdType: idtools.TypeIDPair, IdPair: idtools.IDPair{}}, nil
}
