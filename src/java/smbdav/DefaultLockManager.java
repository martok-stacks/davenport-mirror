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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import javax.servlet.http.HttpServletResponse;

import jcifs.smb.SmbFile;

public class DefaultLockManager implements LockManager {

    protected static final Timer TIMER = new Timer(true);

    protected final Map locks = new HashMap();

    private long defaultTimeout = SmbDAVUtilities.INFINITE_TIMEOUT;

    private long maximumTimeout = SmbDAVUtilities.INFINITE_TIMEOUT;

    public DefaultLockManager() {
        this(SmbDAVUtilities.INFINITE_TIMEOUT,
                SmbDAVUtilities.INFINITE_TIMEOUT);
    }

    public DefaultLockManager(long defaultTimeout) {
        this(defaultTimeout, SmbDAVUtilities.INFINITE_TIMEOUT);
    }

    public DefaultLockManager(long defaultTimeout, long maximumTimeout) {
        setDefaultTimeout(defaultTimeout);
        setMaximumTimeout(maximumTimeout);
    }

    public long getDefaultTimeout() {
        return defaultTimeout;
    }

    public void setDefaultTimeout(long defaultTimeout) {
        this.defaultTimeout = defaultTimeout;
    }

    public long getMaximumTimeout() {
        return maximumTimeout;
    }

    public void setMaximumTimeout(long maximumTimeout) {
        this.maximumTimeout = maximumTimeout;
    }

    public int getLockSupport(SmbFile resource) throws IOException {
        return SHARED_LOCK_SUPPORT | EXCLUSIVE_LOCK_SUPPORT;
    }

    public boolean isLocked(SmbFile resource, String lockToken)
            throws IOException {
        BasicLock lock;
        synchronized (locks) {
            lock = (BasicLock) locks.get(lockToken);
        }
        return coveredBy(resource, lock);
    }

    public Lock[] getActiveLocks(SmbFile resource) throws IOException {
        Set activeLocks = new HashSet();
        synchronized (locks) {
            Iterator lockIterator = locks.values().iterator();
            while (lockIterator.hasNext()) {
                BasicLock lock = (BasicLock) lockIterator.next();
                if (coveredBy(resource, lock)) activeLocks.add(lock);
            }
        }
        return activeLocks.isEmpty() ? null :
                (BasicLock[]) activeLocks.toArray(new BasicLock[0]);
    }

    public SmbFile getLockedResource(SmbFile resource, Principal principal)
            throws IOException {
        return resource;
    }

    public String lock(SmbFile resource, Principal principal, LockInfo lockInfo)
            throws LockException, IOException {
        Log.log(Log.DEBUG, "Locking \"{0}\" for \"{1}\" -- {2}", new Object[] {
                resource, principal, lockInfo });
        synchronized (locks) {
            BasicLock[] activeLocks = (BasicLock[]) getActiveLocks(resource);
            if (activeLocks != null && activeLocks.length > 0) {
                if (lockInfo.isExclusive()) {
                    Log.log(Log.DEBUG,
                            "Cannot lock exclusively (existing lock).");
                    throw new LockException(MethodHandler.SC_LOCKED);
                }
                for (int i = activeLocks.length - 1; i >= 0; i--) {
                    Log.log(Log.DEBUG, "Examining existing lock -- {0}",
                            activeLocks[i]);
                    if (activeLocks[i].isExclusive()) {
                        Log.log(Log.DEBUG, "Cannot obtain lock -- exclusive " +
                                "lock already exists:\n{0}", activeLocks[i]);
                        throw new LockException(MethodHandler.SC_LOCKED);
                    }
                }
            }
            String lockToken = "opaquelocktoken:" +
                    SmbDAVUtilities.generateUuid();
            Lock lock = createLock(resource, principal, lockToken, lockInfo);
            locks.put(lockToken, lock);
            Log.log(Log.DEBUG, "Locked resource \"{0}\":\n{1}", new Object[] {
                    resource, lock });
            return lockToken;
        }
    }

    public void refresh(SmbFile resource, Principal principal,
            String[] lockTokens, long timeout) throws LockException,
                    IOException {
        if (Log.getThreshold() < Log.INFORMATION) {
            StringBuffer tokens = new StringBuffer();
            for (int i = 0; i < lockTokens.length; i++) {
                tokens.append(lockTokens[i]);
                if (i + 1 < lockTokens.length) tokens.append(", ");
            }
            Log.log(Log.DEBUG, "Refreshing locks on \"{0}\" for \"{1}\", " +
                    "Timeout {2}:\n{3}", new Object[] { resource, principal,
                            SmbDAVUtilities.formatTimeout(timeout), tokens });
        }
        synchronized (locks) {
            BasicLock[] activeLocks = (BasicLock[]) getActiveLocks(resource);
            if (activeLocks == null || activeLocks.length == 0) {
                Log.log(Log.DEBUG, "No active locks on \"{0}\"", resource);
                throw new LockException(
                        HttpServletResponse.SC_PRECONDITION_FAILED);
            }
            Set currentLocks = new HashSet();
            for (int i = lockTokens.length - 1; i >= 0; i--) {
                String lockToken = lockTokens[i];
                boolean found = false;
                for (int j = activeLocks.length - 1; j >= 0; j--) {
                    BasicLock activeLock = activeLocks[j];
                    if (lockToken.equals(activeLock.getToken())) {
                        found = true;
                        currentLocks.add(activeLock);
                        Log.log(Log.DEBUG, "Found matching lock -- {0}",
                                activeLock);
                        break;
                    }
                }
                if (!found) {
                    Log.log(Log.DEBUG, "Unable to find matching lock.");
                    throw new LockException(
                            HttpServletResponse.SC_PRECONDITION_FAILED);
                }
            }
            Iterator lockIterator = currentLocks.iterator();
            while (lockIterator.hasNext()) {
                ((BasicLock) lockIterator.next()).refresh(timeout);
            }
        }
    }

    public void unlock(SmbFile resource, Principal principal, String lockToken)
            throws LockException, IOException {
        Log.log(Log.DEBUG, "Unlocking \"{0}\" for \"{1}\" with token {2}",
                new Object[] { resource, principal, lockToken });
        synchronized (locks) {
            BasicLock lock = (BasicLock) locks.get(lockToken);
            if (!coveredBy(resource, lock)) {
                Log.log(Log.DEBUG,
                        "Resource \"{0}\" is not covered by lock -- {1}",
                                new Object[] { resource, lock });
                throw new LockException(
                        HttpServletResponse.SC_PRECONDITION_FAILED);
            }
            Log.log(Log.DEBUG, "Unlocking resource \"{0}\" -- {1}",
                    new Object[] { resource, lock });
            lock.unlock();
        }
    }

    protected BasicLock createLock(SmbFile resource, Principal principal,
            String lockToken, LockInfo lockInfo) throws IOException,
                    LockException {
        return new BasicLock(resource, principal, lockToken, lockInfo);
    }

    private boolean coveredBy(SmbFile resource, BasicLock lock)
            throws IOException {
        if (lock == null || resource == null) return false;
        String path = resource.getCanonicalPath();
        String lockPath = lock.getResource().getCanonicalPath();
        if (path.equals(lockPath)) return true; // same resource
        if (!path.startsWith(lockPath) || !(lockPath.endsWith("/") ||
                path.substring(lockPath.length()).startsWith("/"))) {
            return false;  // not a parent
        }
        return (lock.getDepth() == SmbDAVUtilities.INFINITE_DEPTH);
    }

    protected class BasicLock extends Lock {

        private final SmbFile resource;

        private final Principal principal;

        private final String token;

        private TimerTask task;

        public BasicLock(SmbFile resource, Principal principal, String token,
                LockInfo lockInfo) throws IOException {
            this.resource = resource;
            this.principal = principal;
            this.token = token;
            if (!resource.exists()) resource.createNewFile();
            setExclusive(lockInfo.isExclusive());
            setOwner(lockInfo.getOwner());
            setDepth(lockInfo.getDepth());
            refresh(lockInfo.getTimeout());
        }

        public SmbFile getResource() {
            return resource;
        }

        public String getToken() {
            return token;
        }

        public Principal getPrincipal() {
            return principal;
        }

        public void setTimeout(long timeout) {
            if (timeout == SmbDAVUtilities.UNSPECIFIED_TIMEOUT) {
                timeout = getDefaultTimeout();
            }
            long max = getMaximumTimeout();
            if (max != SmbDAVUtilities.INFINITE_TIMEOUT) {
                if (timeout == SmbDAVUtilities.INFINITE_TIMEOUT) timeout = max;
                if (timeout <= 0) timeout = getDefaultTimeout();
                timeout = Math.min(timeout, max);
            } else if (timeout != SmbDAVUtilities.INFINITE_TIMEOUT) {
                if (timeout <= 0) timeout = getDefaultTimeout();
            }
            super.setTimeout(timeout);
        }

        public void refresh(long timeout) throws IOException {
            // apply timeout bounds checking
            setTimeout(timeout);
            timeout = getTimeout();
            synchronized (this) {
                if (task != null) task.cancel();
                if (timeout == SmbDAVUtilities.INFINITE_TIMEOUT) return;
                task = new TimerTask() {
                    public void run() {
                        try {
                            unlock();
                        } catch (IOException ex) {
                            Log.log(Log.INFORMATION, "Unable to unlock {0} " +
                                    "on {1}: {2}", new Object[] { getToken(),
                                            getResource(), ex });
                        }
                    }
                };
                TIMER.schedule(task, timeout);
            }
            Log.log(Log.DEBUG, "Established/renewed lock on \"{0}\" -- {1}",
                    new Object[] { getResource(), this });
        }

        public void unlock() throws IOException {
            synchronized (this) {
                if (task != null) {
                    task.cancel();
                    task = null;
                }
            }
            synchronized (locks) {
                locks.remove(getToken());
            }
            Log.log(Log.DEBUG, "Released lock on \"{0}\" -- {1}",
                    new Object[] { getResource(), this });
        }

    }

}
