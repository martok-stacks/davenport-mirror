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

import java.io.IOException;

import java.security.Principal;

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import jcifs.smb.LockedFile;
import jcifs.smb.SmbFile;

public class SmbLockManager extends DefaultLockManager {

    private final Map singletons = new HashMap();

    public SmbLockManager() {
        super();
    }

    public SmbLockManager(long defaultTimeout) {
        super(defaultTimeout);
    }

    public SmbLockManager(long defaultTimeout, long maximumTimeout) {
        super(defaultTimeout, maximumTimeout);
    }

    public int getLockSupport(SmbFile resource) throws IOException {
        return EXCLUSIVE_LOCK_SUPPORT;
    }

    public SmbFile getLockedResource(SmbFile resource, Principal principal)
            throws IOException {
        SmbLock lock;
        synchronized (singletons) {
            lock = (SmbLock) singletons.get(resource.getCanonicalPath());
        }
        if (lock == null || principal == null) {
            Log.log(Log.DEBUG,
                    "No locked resource found for {0} (principal {1}).",
                            new Object[] { resource, principal });
            return resource;
        }
        if (!principal.getName().equals(lock.getPrincipal().getName())) {
            Log.log(Log.DEBUG, "Principal {0} does not match lock holder {1}.",
                    new Object[] { principal.getName(),
                            lock.getPrincipal().getName() });
            return resource;
        }
        resource = lock.getResource();
        Log.log(Log.DEBUG, "Obtained locked resource for {0} (principal {1}).",
                new Object[] { resource, principal });
        return resource;
    }

    protected BasicLock createLock(SmbFile resource, Principal principal,
            String lockToken, LockInfo lockInfo) throws IOException,
                    LockException {
        if (!lockInfo.isExclusive()) {
            Log.log(Log.DEBUG, "Client requested a shared lock (unsupported)");
            throw new LockException(HttpServletResponse.SC_BAD_REQUEST);
        }
        return new SmbLock(resource, principal, lockToken, lockInfo);
    }

    protected class SmbLock extends BasicLock {

        public SmbLock(SmbFile resource, Principal principal, String token,
                LockInfo lockInfo) throws IOException, LockException {
            super(resource.isFile() ? new LockedFile(resource) : resource,
                    principal, token, lockInfo);
            String path = resource.getCanonicalPath();
            synchronized (singletons) {
                if (singletons.containsKey(path)) {
                    // already locked? shouldn't be...
                    Log.log(Log.DEBUG, "Already a lock on {0}?",
                            resource);
                    return;
                }
                Log.log(Log.DEBUG, "Installing lock instance for {0}.", path);
                singletons.put(path, this);
            }
        }

        public void unlock() throws IOException {
            super.unlock();
            synchronized (singletons) {
                Log.log(Log.DEBUG, "Removing lock instance for {0}.",
                        getResource());
                singletons.remove(getResource().getCanonicalPath());
            }
            SmbFile resource = getResource();
            if (resource instanceof LockedFile) {
                ((LockedFile) resource).unlock();
            }
        }

    }

}
