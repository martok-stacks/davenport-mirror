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

import java.io.ByteArrayInputStream;

import org.xml.sax.EntityResolver;
import org.xml.sax.InputSource;

/**
 * Entity resolver which prevents external entities from being referenced.
 * This is used to prevent various XML-based attacks.
 *
 * @author Eric Glass
 */
public class BlockedEntityResolver implements EntityResolver {

    /**
     * Singleton resolver instance.
     */ 
    public static final BlockedEntityResolver INSTANCE =
            new BlockedEntityResolver();

    private BlockedEntityResolver() { }

    /**
     * Returns an empty stream in response to an attempt to resolve an
     * external entity, and logs a warning.
     *
     * @param publicId The public identifier of the external entity.
     * @param systemId The system identifier of the external entity.
     * @return An empty <code>InputSource</code>.
     */ 
    public InputSource resolveEntity(String publicId, String systemId) {
        Log.log(Log.WARNING,
                "Blocked attempt to resolve external entity at {0}.", systemId);
        return new InputSource(new ByteArrayInputStream(new byte[0]));
    }

}
