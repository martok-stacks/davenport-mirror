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

package smbdav.filters;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import java.util.Properties;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileFilter;

import smbdav.DavenportFileFilter;
import smbdav.Log;

/**
 * This class inverts the result of an underlying filter; a file will
 * be accepted by the filter only if the underlying filter rejects the
 * file.  This is effectively a logical NOT.
 * <p>
 * This filter accepts a <code>filter</code> parameter containing the
 * underlying filter class.  If the filter class implements the
 * <code>smbdav.DavenportFileFilter</code> interface, the instance will be
 * initialized with a copy of this filter's properties (excluding the
 * "filter" property itself).  For example:
 * <p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;fileFilters&lt;/param-name&gt;
 *     &lt;param-value&gt;myNotFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myNotFilter&lt;/param-name&gt;
 *     &lt;param-value&gt;smbdav.filters.NotFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myNotFilter.filter&lt;/param-name&gt;
 *     &lt;param-value&gt;com.foo.MyFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myNotFilter.subProperty&lt;/param-name&gt;
 *     &lt;param-value&gt;subValue&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * </pre> 
 * <p>
 * The <code>fileFilters</code> parameter declares a single
 * <code>NotFilter</code> ("myNotFilter").  This filter is passed
 * the "filter" property, specifying <code>com.foo.MyFilter</code> as the
 * subfilter class.  This subfilter class is instantiated, and provided a copy
 * of this filter's properties (containing the single property "subProperty"
 * with the value "subValue").  Note that the "filter" property is removed
 * from the properties copy provided to the subfilter.
 *
 * @author Eric Glass
 */ 
public class NotFilter implements DavenportFileFilter {

    private SmbFileFilter filter;

    public void init(Properties properties) throws Exception {
        String filter = properties.getProperty("filter");
        if (filter == null) return;
        SmbFileFilter fileFilter = (SmbFileFilter)
                Class.forName(filter).newInstance();
        Log.log(Log.DEBUG, "Created subfilter {0}", filter);
        if (fileFilter instanceof DavenportFileFilter) {
            Properties props = (Properties) properties.clone();
            props.remove("filter");
            if (Log.getThreshold() < Log.INFORMATION) {
                ByteArrayOutputStream stream = new ByteArrayOutputStream();
                props.list(new PrintStream(stream));
                Object[] args = new Object[] { filter,
                        new String(stream.toByteArray()) };
                Log.log(Log.DEBUG, "Initializing subfilter ({0}):\n{1}", args);
            }
            ((DavenportFileFilter) fileFilter).init(props);
        }
        this.filter = fileFilter;
    }

    public void destroy() {
        if (filter == null) return;
        try {
            if (filter instanceof DavenportFileFilter) {
                ((DavenportFileFilter) filter).destroy();
            }
        } catch (Throwable t) { }
        filter = null;
    }

    public boolean accept(SmbFile file) throws SmbException {
        if (filter == null) {
            Log.log(Log.DEBUG, "No subfilter (rejecting).");
            return false;
        }
        boolean status = !filter.accept(file);
        Log.log(Log.DEBUG, status ?
                "Subfilter rejection for \"{0}\"; accepting." :
                        "Subfilter acceptance for \"{0}\"; rejecting", file);
        return status;
    }

}
