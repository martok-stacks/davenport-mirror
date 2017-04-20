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

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileFilter;

import smbdav.DavenportFileFilter;
import smbdav.Log;

/**
 * This class chains one or more underlying filters together; a
 * file will be accepted if any subfilters accept the file.  This is
 * effectively a logical OR.
 * <p>
 * Subfilters are installed using a mechanism very similar to the global
 * filter installation; this filter accepts a <code>fileFilters</code>
 * parameter containing a list of whitespace-separated subfilter names.
 * An additional parameter is specified for each name, indicating the filter
 * class.  If the filter class implements the
 * <code>smbdav.DavenportFileFilter</code> interface, the instance will be
 * initialized using a <code>java.util.Properties</code> object containing
 * name-value pairs from this filter's properties, scoped by the subfilter's
 * name.  For example:
 * <p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;fileFilters&lt;/param-name&gt;
 *     &lt;param-value&gt;myOrFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myOrFilter&lt;/param-name&gt;
 *     &lt;param-value&gt;smbdav.filters.OrFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myOrFilter.fileFilters&lt;/param-name&gt;
 *     &lt;param-value&gt;mySubFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myOrFilter.mySubFilter&lt;/param-name&gt;
 *     &lt;param-value&gt;com.foo.MyFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myOrFilter.mySubFilter.subProperty&lt;/param-name&gt;
 *     &lt;param-value&gt;subValue&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * </pre> 
 * <p>
 * The <code>fileFilters</code> parameter declares a single
 * <code>OrFilter</code> ("myOrFilter").  This filter is passed
 * its own "fileFilters" property, containing the single subfilter name
 * "mySubFilter".  A corresponding property is provided, specifying
 * <code>com.foo.MyFilter</code> as the subfilter class.
 * This subfilter class is instantiated, and provided its own
 * set of properties (containing the single property "subProperty" with the
 * value "subValue").  Note that the subfilter's namespace prefix
 * ("mySubFilter.") will be stripped off when the properties are delivered to
 * the subfilter instance.
 *
 * @author Eric Glass
 */ 
public class OrFilter implements DavenportFileFilter {

    private SmbFileFilter[] filters;

    public void init(Properties properties) throws Exception {
        String fileFilters = properties.getProperty("fileFilters");
        if (fileFilters == null) return;
        List filters = new ArrayList();
        StringTokenizer tokenizer = new StringTokenizer(fileFilters);
        while (tokenizer.hasMoreTokens()) {
            String filter = tokenizer.nextToken();
            SmbFileFilter fileFilter = (SmbFileFilter) Class.forName(
                    properties.getProperty(filter)).newInstance();
            Log.log(Log.DEBUG, "Created subfilter {0}: {1}",
                    new Object[] { filter, fileFilter.getClass() });
            if (fileFilter instanceof DavenportFileFilter) {
                Properties props = new Properties();
                Enumeration parameters = properties.propertyNames();
                String prefix = filter + ".";
                int prefixLength = prefix.length();
                while (parameters.hasMoreElements()) {
                    String parameter = (String) parameters.nextElement();
                    if (parameter.startsWith(prefix)) {
                        props.setProperty(parameter.substring(prefixLength),
                                properties.getProperty(parameter));
                    }
                }
                if (Log.getThreshold() < Log.INFORMATION) {
                    ByteArrayOutputStream stream = new ByteArrayOutputStream();
                    props.list(new PrintStream(stream));
                    Object[] args = new Object[] { filter,
                            fileFilter.getClass(),
                                    new String(stream.toByteArray()) };
                    Log.log(Log.DEBUG,
                            "Initializing subfilter \"{0}\" ({1}):\n{2}", args);
                }
                ((DavenportFileFilter) fileFilter).init(props);
            }
            filters.add(fileFilter);
        }
        if (!filters.isEmpty()) {
            this.filters = (SmbFileFilter[])
                    filters.toArray(new SmbFileFilter[0]);
        }
    }

    public void destroy() {
        if (filters == null) return;
        for (int i = filters.length - 1; i >= 0; i--) {
            try {
                if (filters[i] instanceof DavenportFileFilter) {
                    ((DavenportFileFilter) filters[i]).destroy();
                }
            } catch (Throwable t) { }
            filters[i] = null;
        }
        filters = null;
    }

    public boolean accept(SmbFile file) throws SmbException {
        if (filters == null) {
            Log.log(Log.DEBUG, "No subfilters (accepting).");
            return true;
        }
        for (int i = 0; i < filters.length; i++) {
            if (filters[i].accept(file)) {
                Log.log(Log.DEBUG,
                        "Subfilter accepted file \"{0}\"; accepting. ({1})",
                                new Object[] { file, filters[i].getClass() });
                return true;
            }
        }
        Log.log(Log.DEBUG, "No subfilter acceptances for \"{0}\"; rejecting.",
                file);
        return false;
    }

}
