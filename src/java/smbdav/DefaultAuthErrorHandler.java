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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jcifs.smb.NtStatus;
import jcifs.smb.SmbAuthException;

/**
 * This is the default Davenport <code>ErrorHandler</code> for authentication
 * exceptions.  This class processes authentication errors according to the
 * <code>errorHandler.authenticationFailureBehavior</code> and
 * <code>errorHandler.sendError</code> settings.
 *
 * @author Eric Glass
 */
public class DefaultAuthErrorHandler implements ErrorHandler {

    public static final int AUTHENTICATE_BEHAVIOR = 0;

    public static final int FORBIDDEN_BEHAVIOR = 1;

    public static final int UNAUTHORIZED_BEHAVIOR = 2;

    public static final int NOT_FOUND_BEHAVIOR = 3;

    public static final int IGNORE_BEHAVIOR = 4;

    private int authFailureBehavior = AUTHENTICATE_BEHAVIOR;

    private boolean sendError;

    public void init(ServletConfig config) throws ServletException {
        String authFailureBehavior = config.getInitParameter(
                "errorHandler.authenticationFailureBehavior");
        if (authFailureBehavior != null) {
            if ("forbidden".equalsIgnoreCase(authFailureBehavior)) {
                this.authFailureBehavior = FORBIDDEN_BEHAVIOR;
            } else if ("unauthorized".equalsIgnoreCase(authFailureBehavior)) {
                this.authFailureBehavior = UNAUTHORIZED_BEHAVIOR;
            } else if ("authenticate".equalsIgnoreCase(authFailureBehavior)) {
                this.authFailureBehavior = AUTHENTICATE_BEHAVIOR;
            } else if ("notfound".equalsIgnoreCase(authFailureBehavior)) {
                this.authFailureBehavior = NOT_FOUND_BEHAVIOR;
            } else if ("ignore".equalsIgnoreCase(authFailureBehavior)) {
                this.authFailureBehavior = IGNORE_BEHAVIOR;
            } else {
                throw new UnavailableException(SmbDAVUtilities.getResource(
                        DefaultAuthErrorHandler.class,
                                "illegalAuthenticationFailureBehavior",
                                        new Object[] { authFailureBehavior },
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
     * an error.  This implementation processes authentication errors
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
        if (!(throwable instanceof SmbAuthException)) throw throwable;
        SmbAuthException ex = (SmbAuthException) throwable;
        if (ex.getNtStatus() == NtStatus.NT_STATUS_ACCESS_VIOLATION) {
            Log.log(Log.DEBUG, "Access violation (expired credentials).");
            throw new ErrorHandlerException(ex);
        }
        switch (authFailureBehavior) {
        case AUTHENTICATE_BEHAVIOR:
            Log.log(Log.DEBUG,
                    "Auth Error handler propagating for authentication.");
            throw new ErrorHandlerException(ex);
        case FORBIDDEN_BEHAVIOR:
            Log.log(Log.DEBUG, "Auth Error handler sending Forbidden (403).");
            if (sendError) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN,
                        SmbDAVUtilities.getResource(
                                DefaultAuthErrorHandler.class, "forbidden",
                                        new Object[] { ex.getMessage() },
                                                request.getLocale()));
            } else {
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
                response.flushBuffer();
            }
            break;
        case UNAUTHORIZED_BEHAVIOR:
            Log.log(Log.DEBUG,
                    "Auth Error handler sending Unauthorized (401).");
            if (sendError) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        SmbDAVUtilities.getResource(
                                DefaultAuthErrorHandler.class, "unauthorized",
                                        new Object[] { ex.getMessage() },
                                                request.getLocale()));
            } else {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.flushBuffer();
            }
            break;
        case NOT_FOUND_BEHAVIOR:
            Log.log(Log.DEBUG, "Auth Error handler sending Not Found (404).");
            if (sendError) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND,
                        SmbDAVUtilities.getResource(
                                DefaultAuthErrorHandler.class, "notfound",
                                        new Object[] { ex.getMessage() },
                                                request.getLocale()));
            } else {
                response.setStatus(HttpServletResponse.SC_NOT_FOUND);
                response.flushBuffer();
            }
            break;
        case IGNORE_BEHAVIOR:
            Log.log(Log.DEBUG, "Auth Error handler ignoring (sending 200).");
            break;
        default:
            throw new IllegalStateException();
        }
    }

}

