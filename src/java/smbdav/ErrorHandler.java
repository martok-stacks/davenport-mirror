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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A class can implement the <code>ErrorHandler</code> interface when it
 * wishes to handle errors thrown by the method handler for the current
 * request.  The Davenport servlet installs error handlers in a chain.
 * The first installed handler is invoked and given the chance to handle
 * the error/exception; if it rethrows the exception, the next installed
 * handler is invoked.  If unhandled, the error is thrown from the servlet
 * and handled by the container.
 * To install a handler,
 * <ul>
 * <li>Create a class implementing the <code>ErrorHandler</code>
 * interface.  The implementing class must also provide a no-arg
 * constructor.</li>
 * <li>Add your handler's class name to the <code>errorHandlers</code>
 * parameter in the Davenport deployment descriptor.  Entries are
 * separated by whitespace; the handlers are invoked in the order in which
 * they are declared in the descriptor.</li>
 * </ul>
 * As an example, if you have a class <code>com.foo.MyErrorHandler</code>
 * implementing <code>smbdav.ErrorHandler</code>, you would add the following
 * to the Davenport deployment descriptor:
 * <p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;errorHandlers&lt;/param-name&gt;
 *     &lt;param-value&gt;com.foo.MyErrorHandler&lt;/param-value&gt;
 * &lt;/init-param&gt;
 * </pre>
 * <p>
 * If no handlers are specified, Davenport installs instances of
 * <code>smbdav.DefaultAuthErrorHandler</code> and
 * <code>smbdav.DefaultIOErrorHandler</code>.  If installing your own
 * handler, it may be desirable to include these as "fallback" handlers:
 * <p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;errorHandlers&lt;/param-name&gt;
 *     &lt;param-value&gt;com.foo.MyErrorHandler
 *                  smbdav.DefaultAuthErrorHandler
 *                  smbdav.DefaultIOErrorHandler&lt;/param-value&gt;
 * &lt;/init-param&gt;
 * </pre>
 *
 * @author Eric Glass
 */
public interface ErrorHandler {

    /**
     * Called by the Davenport servlet to indicate that the handler is being
     * placed into service.  Semantics are identical to the <code>Servlet</code>
     * <code>init</code> method; the method is called exactly once after
     * instantiation.
     * 
     * @param config a <code>ServletConfig</code> object containing
     * the Davenport servlet's configuration and initialization parameters.
     * @throws ServletException If an error occurs during initialization.
     */
    public void init(ServletConfig config) throws ServletException;

    /**
     * Called by the Davenport servlet to indicate that the handler is being
     * taken out of service.  Semantics are identical to the
     * <code>Servlet</code> <code>destroy</code> method.  This method
     * gives the handler an opportunity to clean up any resources that
     * are being held.  After this method has been called, the
     * <code>handle</code> method will not be invoked again.
     */
    public void destroy();

    /**
     * Called by the Davenport servlet to allow the error handler to process
     * an error.  If the handler cannot process the error appropriately, it
     * should be rethrown to allow processing by other entries in the
     * handler chain.  It is permissible for handlers to throw a different
     * error, if processing the original error itself fails.
     * 
     * @param throwable The error that is being presented for handling.
     * @param request The servlet request object.
     * @param response The servlet response object.
     * @throws Throwable The presented error, if it cannot be processed
     * by this handler.
     */
    public void handle(Throwable throwable, HttpServletRequest request,
            HttpServletResponse response) throws Throwable;

}

