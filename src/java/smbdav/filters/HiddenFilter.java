/* Davenport WebDAV SMB Gateway
 * Copyright (C) 2004  Eric Glass
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package smbdav.filters;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileFilter;

import smbdav.Log;

/**
 * This filter rejects hidden resources.
 *
 * @author Eric Glass
 */ 
public class HiddenFilter implements SmbFileFilter {

    public boolean accept(SmbFile file) throws SmbException {
        boolean status = !file.isHidden();
        Log.log(Log.DEBUG, status ? "File \"{0}\" is not hidden; accepting" :
                "File \"{0}\" is hidden; rejecting", file);
        return status;
    }

}
