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

package smbdav.properties;

import java.io.IOException;

import javax.servlet.http.HttpServletResponse;

import jcifs.smb.SmbFile;

import org.w3c.dom.Element;

import smbdav.AbstractProperty;
import smbdav.Davenport;
import smbdav.LockManager;

/**
 * Provides access to the <code>supportedlock</code> property.
 * This implementation returns the server's lock capability.
 *
 * @author Eric Glass
 */
public class SupportedLockProperty extends AbstractProperty {

    public int retrieve(SmbFile file, Element element) throws IOException {
        LockManager lockManager = (LockManager)
                getServletConfig().getServletContext().getAttribute(
                        Davenport.LOCK_MANAGER);
        if (lockManager == null) return HttpServletResponse.SC_NOT_FOUND;
        int lockSupport = lockManager.getLockSupport(file);
        if (lockSupport == LockManager.NO_LOCK_SUPPORT) {
            return HttpServletResponse.SC_OK;
        }
        if ((lockSupport & LockManager.EXCLUSIVE_LOCK_SUPPORT) ==
                LockManager.EXCLUSIVE_LOCK_SUPPORT) {
            element.appendChild(createLockEntry(element, "exclusive"));
        }
        if ((lockSupport & LockManager.SHARED_LOCK_SUPPORT) ==
                LockManager.SHARED_LOCK_SUPPORT) {
            element.appendChild(createLockEntry(element, "shared"));
        }
        return HttpServletResponse.SC_OK;
    }

    private Element createLockEntry(Element base, String scope) {
        Element lockEntry = createElement(base, "lockentry");
        Element lockScope = createElement(lockEntry, "lockscope");
        lockScope.appendChild(createElement(lockScope, scope));
        lockEntry.appendChild(lockScope);
        Element lockType = createElement(lockEntry, "locktype");
        lockType.appendChild(createElement(lockType, "write"));
        lockEntry.appendChild(lockType);
        return lockEntry;
    }

    private Element createElement(Element base, String tag) {
        String namespace = base.getNamespaceURI();
        if (namespace != null) {
            String prefix = base.getPrefix();
            return base.getOwnerDocument().createElementNS(namespace,
                    prefix == null ? tag : prefix + ":" + tag);
        }
        return base.getOwnerDocument().createElement(tag);
    }

}
