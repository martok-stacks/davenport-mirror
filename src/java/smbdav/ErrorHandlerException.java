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

/**
 * An <code>ErrorHandlerException</code> wraps an underlying
 * <code>Throwable</code> object, and is thrown to circumvent the Davenport
 * error handling chain.  Rather than passing this exception on to the next
 * handler in the chain, error handling will stop with the intent to throw
 * the underlying throwable object (if non-<code>null</code>).
 *
 * @author Eric Glass 
 */
public class ErrorHandlerException extends Exception {

    private final Throwable throwable;

    /**
     * Creates an <code>ErrorHandlerException</code> with no underlying
     * throwable object.  This is used to simply circumvent the error
     * handler chain.
     */
    public ErrorHandlerException() {
        this(null);
    }

    /**
     * Creates an <code>ErrorHandlerException</code> wrapping the specified
     * throwable.
     *
     * @param throwable The <code>Throwable</code> object that is intended
     * to be thrown out to the container.
     */
    public ErrorHandlerException(Throwable throwable) {
        super();
        this.throwable = throwable;
    }

    /**
     * Returns the wrapped <code>Throwable</code> object for this
     * <code>ErrorHandlerException</code>.
     */
    public Throwable getThrowable() {
        return throwable;
    }

}
