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

package smbdav;

import java.util.Properties;

public class SmbLockManagerFactory extends LockManagerFactory {

    private long defaultTimeout = SmbDAVUtilities.INFINITE_TIMEOUT;

    private long maximumTimeout = SmbDAVUtilities.INFINITE_TIMEOUT;

    public void setProperties(Properties properties) {
        String defaultTimeout = properties.getProperty("defaultTimeout");
        if (defaultTimeout != null) {
            this.defaultTimeout = Long.parseLong(defaultTimeout);
        }
        String maximumTimeout = properties.getProperty("maximumTimeout");
        if (maximumTimeout != null) {
            this.maximumTimeout = Long.parseLong(maximumTimeout);
        }
    }

    public LockManager newLockManager() {
        return new SmbLockManager(defaultTimeout, maximumTimeout);
    }

}

