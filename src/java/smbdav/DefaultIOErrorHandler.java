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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * This is the default Davenport <code>ErrorHandler</code> for IO
 * exceptions.  This class processes authentication errors according to the
 * <code>errorHandler.ioFailureBehavior</code> and
 * <code>errorHandler.sendError</code> settings.
 *
 * @author Eric Glass
 */
public class DefaultIOErrorHandler implements ErrorHandler {

    public static final int SERVER_ERROR_BEHAVIOR = 0;

    public static final int NOT_FOUND_BEHAVIOR = 1;

    public static final int GONE_BEHAVIOR = 2;

    public static final int IGNORE_BEHAVIOR = 3;

    private int ioFailureBehavior = SERVER_ERROR_BEHAVIOR;

    private boolean sendError;

    public void init(ServletConfig config) throws ServletException {
        String ioFailureBehavior = config.getInitParameter(
                "errorHandler.ioFailureBehavior");
        if (ioFailureBehavior != null) {
            if ("notfound".equalsIgnoreCase(ioFailureBehavior)) {
                this.ioFailureBehavior = NOT_FOUND_BEHAVIOR;
            } else if ("servererror".equalsIgnoreCase(ioFailureBehavior)) {
                this.ioFailureBehavior = SERVER_ERROR_BEHAVIOR;
            } else if ("gone".equalsIgnoreCase(ioFailureBehavior)) {
                this.ioFailureBehavior = GONE_BEHAVIOR;
            } else if ("ignore".equalsIgnoreCase(ioFailureBehavior)) {
                this.ioFailureBehavior = IGNORE_BEHAVIOR;
            } else {
                throw new UnavailableException(SmbDAVUtilities.getResource(
                        DefaultIOErrorHandler.class,
                                "illegalIOFailureBehavior",
                                        new Object[] { ioFailureBehavior },
                                                null));
            }
        }
        String sendError = config.getInitParameter("errorHandler.sendError");
        this.sendError = (sendError == null) ? true :
                Boolean.valueOf(sendError).booleanValue();
    }

    public void destroy() { }

    /**
     * Called by the Davenport servlet to allow the error handler to process
     * an error.  This implementation processes IO errors
     * according to the configured settings.  All other errors are thrown
     * back to the caller for further processing.
     * 
     * @param throwable The error that is being presented for handling.
     * @param request The servlet request object.
     * @param response The servlet response object.
     * @throws Throwable The presented error, if it cannot be processed
     * by this handler.
     */
    public void handle(Throwable throwable, HttpServletRequest request,
            HttpServletResponse response) throws Throwable {
        if (!(throwable instanceof IOException)) {
            throw throwable;
        }
        switch (ioFailureBehavior) {
        case SERVER_ERROR_BEHAVIOR:
            Log.log(Log.DEBUG, "IO Error handler sending Server Error (500).");
            if (sendError) {
                response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                        SmbDAVUtilities.getResource(
                                DefaultIOErrorHandler.class, "servererror",
                                        new Object[] { throwable.getMessage() },
                                                request.getLocale()));
            } else {
                response.setStatus(
                        HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
                response.flushBuffer();
            }
            break;
        case NOT_FOUND_BEHAVIOR:
            Log.log(Log.DEBUG, "IO Error handler sending Not Found (404).");
            if (sendError) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND,
                        SmbDAVUtilities.getResource(
                                DefaultIOErrorHandler.class, "notfound",
                                        new Object[] { throwable.getMessage() },
                                                request.getLocale()));
            } else {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                response.flushBuffer();
            }
            break;
        case GONE_BEHAVIOR:
            Log.log(Log.DEBUG, "IO Error handler sending Gone (410).");
            if (sendError) {
                response.sendError(HttpServletResponse.SC_GONE,
                        SmbDAVUtilities.getResource(
                                DefaultIOErrorHandler.class, "gone",
                                        new Object[] { throwable.getMessage() },
                                                request.getLocale()));
            } else {
                response.setStatus(HttpServletResponse.SC_GONE);
                response.flushBuffer();
            }
            break;
        case IGNORE_BEHAVIOR:
            Log.log(Log.DEBUG, "IO Error handler ignoring (sending 200).");
            break;
        default:
            throw new IllegalStateException();
        }
    }

}

