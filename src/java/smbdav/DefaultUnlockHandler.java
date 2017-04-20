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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;

/**
 * Default implementation of a handler for requests using the WebDAV UNLOCK
 * method.
 *
 * @author Eric Glass
 */
public class DefaultUnlockHandler extends AbstractHandler {

    /**
     * Services requests which use the WebDAV UNLOCK method.
     *
     * @param request The request being serviced.
     * @param response The servlet response.
     * @param auth The user's authentication information.
     * @throws ServletException If an application error occurs.
     * @throws IOException If an IO error occurs while handling the request.
     *
     */
    public void service(HttpServletRequest request,
            HttpServletResponse response, NtlmPasswordAuthentication auth)
                    throws ServletException, IOException {
        LockManager lockManager = getLockManager();
        if (lockManager == null) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                    SmbDAVUtilities.getResource(DefaultUnlockHandler.class,
                            "noLockManager", null, request.getLocale()));
            return;
        }
        SmbFile file = getSmbFile(request, auth);
        Log.log(Log.DEBUG, "UNLOCK Request for resource \"{0}\".", file);
        int result = checkLockOwnership(request, file);
        if (result != HttpServletResponse.SC_OK) {
            response.sendError(result);
            return;
        }
        result = checkConditionalRequest(request, file);
        if (result != HttpServletResponse.SC_OK) {
            response.setStatus(result);
            response.flushBuffer();
            return;
        }
        String lockToken = request.getHeader("Lock-Token");
        if (lockToken == null || !((lockToken = lockToken.trim()).startsWith(
                "<") && lockToken.endsWith(">"))) {
            Log.log(Log.INFORMATION,
                    "Invalid lock token presented to UNLOCK: {0}", lockToken);
            response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            response.flushBuffer();
            return;
        }
        lockToken = lockToken.substring(1, lockToken.length() - 1);
        try {
            lockManager.unlock(file, getPrincipal(request), lockToken);
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
        } catch (LockException ex) {
            response.setStatus(ex.getStatus());
        }
        response.flushBuffer();
    }

}
