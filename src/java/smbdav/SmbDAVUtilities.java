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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.text.DateFormat;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.Hashtable;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.SimpleTimeZone;
import java.util.TimeZone;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

/**
 * This class contains static utility methods for the Davenport servlet
 * and its associated classes.
 *
 * @author Eric Glass
 */
public class SmbDAVUtilities {

    private static final DateFormat CREATION_FORMAT =
            new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US);

    private static final DateFormat LAST_MODIFIED_FORMAT =
            new SimpleDateFormat("E, dd MMM yyyy HH:mm:ss z", Locale.US);

    private static MessageDigest DIGEST;

    static {
        TimeZone gmt = new SimpleTimeZone(0, "GMT");
        CREATION_FORMAT.setTimeZone(gmt);
        LAST_MODIFIED_FORMAT.setTimeZone(gmt);
        try {
            DIGEST = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(getResource(SmbDAVUtilities.class,
                    "md5Unavailable", null, null));
        }
    }

    private SmbDAVUtilities() { }

    /**
     * Returns the specified resource string value.
     *
     * @param context A class representing the context for the resource
     * string.
     * @param resource The resource name.
     * @param parameters Substitution parameters for the message.
     * @param locale The desired locale.
     * @return A <code>String</code> containing the resource value.
     */
    public static String getResource(Class context, String resource,
            Object[] parameters, Locale locale) {
        ResourceBundle resources = (locale == null) ?
                ResourceBundle.getBundle("smbdav.Resources") :
                        ResourceBundle.getBundle("smbdav.Resources", locale);
        String pattern = (context != null) ? resources.getString(
                context.getName() + "." + resource) :
                        resources.getString(resource);
        return (parameters == null) ? pattern :
                MessageFormat.format(pattern, parameters);
    }

    /**
     * Formats a timestamp (representing milliseconds since the epoch)
     * as used in the WebDAV <code>creationdate</code> property.
     *
     * @param creation The creation timestamp, represented as the number
     * of milliseconds since midnight, January 1, 1970 UTC.
     * @return A <code>String</code> containing the formatted result.
     */
    public static String formatCreationDate(long creation) {
        synchronized (CREATION_FORMAT) {
            return CREATION_FORMAT.format(new Date(creation));
        }
    }

    /**
     * Formats a timestamp (representing milliseconds since the epoch)
     * as used in the WebDAV <code>getlastmodified</code> property.
     *
     * @param lastModified The last modification timestamp, represented
     * as the number of milliseconds since midnight, January 1, 1970 UTC.
     * @return A <code>String</code> containing the formatted result.
     */
    public static String formatGetLastModified(long lastModified) {
        synchronized (LAST_MODIFIED_FORMAT) {
            return LAST_MODIFIED_FORMAT.format(new Date(lastModified));
        }
    }

    /**
     * Returns the entity tag for the specified resource.  The returned
     * string uniquely identifies the current incarnation of the given
     * resource.
     *
     * @param file The resource whose entity tag is to be retrieved.
     * @return A <code>String</code> containing the entity tag for the
     * resource.
     */
    public static String getETag(SmbFile file) {
        if (file == null) return null;
        try {
            if (!file.exists()) return null;
            String key = file.toString() + ":" +
                    Long.toHexString(file.lastModified());
            byte[] hashBytes = null;
            synchronized (DIGEST) {
                hashBytes = DIGEST.digest(key.getBytes("UTF-8"));
            }
            StringBuffer hash = new StringBuffer();
            int count = hashBytes.length;
            for (int i = 0; i < count; i++) {
                hash.append(Integer.toHexString((hashBytes[i] >> 4) & 0x0f));
                hash.append(Integer.toHexString(hashBytes[i] & 0x0f));
            }
            return "\"" + hash.toString() + "\"";
        } catch (IOException ex) {
            return null;
        }
    }

}
