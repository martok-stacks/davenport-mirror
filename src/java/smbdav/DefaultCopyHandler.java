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
import jcifs.smb.SmbFile;

/**
 * Default implementation of a handler for requests using the WebDAV
 * COPY method.
 *
 * @author Eric Glass
 */
public class DefaultCopyHandler extends AbstractHandler {

    /**
     * Services requests which use the WebDAV COPY method.
     * This implementation copies the source file to the destination.
     * <br>
     * If the source file does not exist, a 404 (Not Found) error is sent
     * to the client.
     * <br>
     * If the destination is not specified, a 400 (Bad Request) error
     * is sent to the client.
     * <br>
     * If the source and destination specify the same resource, a 403
     * (Forbidden) error is sent to the client.
     * <br>
     * If the destination already exists, and the client has sent the
     * "Overwrite" request header with a value of "T", then the request
     * succeeds and the file is overwritten.  If the "Overwrite" header is
     * not provided, a 412 (Precondition Failed) error is sent to the client.
     *
     * @param request The request being serviced.
     * @param response The servlet response.
     * @param auth The user's authentication information.
     * @throws SerlvetException If an application error occurs.
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
        String destination = getSmbURL(request,
                request.getHeader("Destination"));
        if (destination == null) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        SmbFile destinationFile = createSmbFile(destination, auth);
        if (destinationFile.equals(file)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN,
                    SmbDAVUtilities.getResource(DefaultCopyHandler.class,
                            "sameResource", null, request.getLocale()));
            return;
        }
        boolean overwritten = false;
        if (destinationFile.exists()) {
            if ("T".equalsIgnoreCase(request.getHeader("Overwrite"))) {
                destinationFile.delete();
                overwritten = true;
            } else {
                response.sendError(HttpServletResponse.SC_PRECONDITION_FAILED);
                return;
            }
        }
        file.copyTo(destinationFile);
        response.setStatus(overwritten ? HttpServletResponse.SC_NO_CONTENT :
                HttpServletResponse.SC_CREATED);
        response.setContentLength(0);
    }

}
