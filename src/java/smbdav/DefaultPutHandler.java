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

import java.io.InputStream;
import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileOutputStream;

/**
 * Default implementation of a handler for requests using the HTTP PUT
 * method.
 *
 * @author Eric Glass
 */
public class DefaultPutHandler extends AbstractHandler {

    /**
     * Services requests which use the HTTP PUT method.
     * This implementation uploads the content to the specified location.
     * <br>
     * If the content length is not specified, a 411 (Length Required) error
     * is sent to the client.
     * <br>
     * If the resource exists and is a collection, a 405 (Method Not Allowed)
     * error is sent to the client.
     * <br>
     * If the parent collection does not exist, a 409 (Conflict) error is
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
        int length = request.getContentLength();
        if (length < 0) {
            response.sendError(HttpServletResponse.SC_LENGTH_REQUIRED);
            return;
        }
        SmbFile file = getSmbFile(request, auth);
        boolean existsCurrently = file.exists();
        if (existsCurrently && !file.isFile()) {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED,
                    SmbDAVUtilities.getResource(DefaultPutHandler.class,
                            "collectionTarget", null, request.getLocale()));
            return;
        }
        SmbFile parent = createSmbFile(file.getParent(), auth);
        if (!(parent.exists() && parent.isDirectory())) {
            response.sendError(HttpServletResponse.SC_CONFLICT);
            return;
        }
        int result = checkConditionalRequest(request, file);
        if (result != HttpServletResponse.SC_OK) {
            response.setStatus(result);
            response.setContentLength(0);
            response.flushBuffer();
            return;
        }
        InputStream input = request.getInputStream();
        SmbFileOutputStream output = new SmbFileOutputStream(file);
        byte[] buf = new byte[8192];
        int count;
        while ((count = input.read(buf)) != -1) {
            output.write(buf, 0, count);
        }
        output.flush();
        output.close();
        response.setContentLength(0);
        response.setStatus(HttpServletResponse.SC_CREATED);
        response.setHeader("Location", request.getRequestURL().toString());
        response.setHeader("Allow", "OPTIONS, HEAD, GET, DELETE, PROPFIND, " +
                "PROPPATCH, COPY, MOVE, PUT");
        response.flushBuffer();
    }

}
