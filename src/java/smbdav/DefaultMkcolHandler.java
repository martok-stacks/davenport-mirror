/* Davenport WebDAV SMB Gateway
 * Copyright (C) 2003  Eric Glass
 * Copyright (C) 2003  Ronald Tschalär
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
 * Default implementation of a handler for requests using the WebDAV
 * MKCOL method.
 *
 * @author Eric Glass
 */
public class DefaultMkcolHandler extends AbstractHandler {

    /**
     * Services requests which use the WebDAV MKCOL method.
     * This implementation creates a directory at the specified location.
     * <br>
     * If the specified directory already exists, a 405 (Method Not Allowed)
     * error is sent to the client.
     * <br>
     * If the directory could not be created (the parent is not a share or
     * directory, or does not exist) a 409 (Conflict) error is sent to the
     * client.
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
        if (file.exists()) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
            return;
        }
        try {
            file.mkdir();
            response.setStatus(HttpServletResponse.SC_CREATED);
            response.setContentLength(0);
        } catch (SmbAuthException ex) {
            throw ex;
        } catch (SmbException ex) {
            response.sendError(HttpServletResponse.SC_CONFLICT,
                    ex.getMessage());
        }
    }

}
