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

import java.security.Principal;

/**
 * Represents an active lock.
 *
 * @author Eric Glass
 */
public abstract class Lock extends LockInfo {

    /**
     * Returns the token associated with this lock.
     * 
     * @return A <code>String</code> containing the associated lock
     * token URI (typically an "opaquelocktoken" URI).
     */
    public abstract String getToken();

    /**
     * Returns the principal owning this lock.
     *
     * @return A <code>Principal</code> representing the lock owner.
     */ 
    public abstract Principal getPrincipal();

    public String toString() {
        StringBuffer buffer = new StringBuffer("token: ");
        buffer.append(getToken()).append("; ");
        buffer.append("principal: ");
        buffer.append(getPrincipal()).append("; ");
        buffer.append(super.toString());
        return buffer.toString();
    }

}
