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
 * Default implementation of a handler for requests using the HTTP OPTIONS
 * method.
 *
 * @author Eric Glass
 */
public class DefaultOptionsHandler extends AbstractHandler {

    /**
     * Services requests which use the HTTP OPTIONS method.
     * This implementation provides the list of supported methods for
     * the target resource.
     * <br>
     * If the user does not have sufficient privileges to query the
     * resource, a 401 (Unauthorized) error is sent to the client.
     *
     * @param request The request being serviced.
     * @param response The servlet response.
     * @param auth The user's authentication information.
     * @throws SerlvetException If an application error occurs.
     * @throws IOException If an IO error occurs while handling the request.
     */
    public void service(HttpServletRequest request,
            HttpServletResponse response, NtlmPasswordAuthentication auth)
                    throws IOException, ServletException {
        response.setHeader("DAV", "1");
        response.setHeader("MS-Author-Via", "DAV");
        SmbFile file = getSmbFile(request, auth);
        if (file.exists()) {
            if (file.isFile()) {
                response.setHeader("Allow", "OPTIONS, HEAD, GET, DELETE, " +
                        "PROPFIND, PROPPATCH, COPY, MOVE, PUT");
            } else {
                response.setHeader("Allow", "OPTIONS, HEAD, GET, DELETE, " +
                        "PROPFIND, PROPPATCH, COPY, MOVE");
            }
        } else {
            response.setHeader("Allow", "OPTIONS, MKCOL, PUT, POST");
        }
    }

}
