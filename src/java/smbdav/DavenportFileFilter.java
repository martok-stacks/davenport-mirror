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

import java.util.Properties;

import jcifs.smb.SmbFileFilter;

/**
 * This extends the <code>jcifs.smb.SmbFileFilter</code> interface to allow
 * for configuration via a set of initialization properties.
 * <p>
 * Filters are installed via the <code>fileFilters</code> parameter in the
 * Davenport deployment descriptor.  This parameter contains a list of
 * whitespace-separated filter names; an additional parameter is specified for
 * each name, indicating the filter class.  If the filter class implements
 * the <code>smbdav.DavenportFileFilter</code> interface, the instance will
 * be initialized using a <code>java.util.Properties</code> object containing
 * name-value pairs from the deployment descriptor, scoped by the filter's
 * name.  For example:
 * <p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;fileFilters&lt;/param-name&gt;
 *     &lt;param-value&gt;myFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myFilter&lt;/param-name&gt;
 *     &lt;param-value&gt;com.foo.MyFilter&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * &lt;init-param&gt;
 *     &lt;param-name&gt;myFilter.myProperty&lt;/param-name&gt;
 *     &lt;param-value&gt;myValue&lt;/param-value&gt; 
 * &lt;/init-param&gt;
 * </pre> 
 * <p>
 * The <code>fileFilters</code> parameter declares a single filter, named
 * "myFilter".  The corresponding <code>myFilter</code> parameter specifies
 * the filter class ("<code>com.foo.MyFilter</code>").  A
 * <code>java.util.Properties</code> object will be created, containing the
 * single property "myProperty" with value "myValue".  Note that the
 * filter's namespace prefix ("myFilter.") will be stripped off when the
 * properties are delivered to the filter instance.
 *
 * @author Eric Glass
 */ 
public interface DavenportFileFilter extends SmbFileFilter {

    /**
     * Initializes the filter with the provided properties.
     *
     * @param properties The filter's initialization properties.
     * @throws Exception If an error occurs during initialization.
     */ 
    public void init(Properties properties) throws Exception;

    /**
     * Destroys the filter instance.
     */
    public void destroy();

}
