/* Davenport WebDAV SMB Gateway
 * Copyright (C) 2003  Eric Glass
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
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

/**
 * Default implementation of a handler for requests using the HTTP DELETE
 * method.
 *
 * @author Eric Glass
 */
public class DefaultDeleteHandler extends AbstractHandler {

    /**
     * Services requests which use the HTTP DELETE method.
     * This implementation deletes the specified file
     * <br>
     * If the specified file does not exist, a 404 (Not Found) error is
     * sent to the client.
     * <br>
     * If the user does not have sufficient privileges to perform the
     * operation, a 401 (Unauthorized) error is sent to the client.
     *
     * @param request The request being serviced.
     * @param response The servlet response.
     * @param auth The user's authentication information.
     * @throws ServletException If an application error occurs.
     * @throws IOException If an IO error occurs while handling the request.
     */
    public void service(HttpServletRequest request,
            HttpServletResponse response, NtlmPasswordAuthentication auth)
                    throws ServletException, IOException {
        SmbFile file = getSmbFile(request, auth);
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        try {
            file.delete();
            response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            response.setContentLength(0);
            response.flushBuffer();
        } catch (SmbAuthException ex) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                    SmbDAVUtilities.getResource(DefaultDeleteHandler.class,
                            "accessDenied", null, request.getLocale()));
        }
    }

}
