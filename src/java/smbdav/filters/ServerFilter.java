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

import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.StringTokenizer;

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

import smbdav.DavenportFileFilter;
import smbdav.Log;

/**
 * This class filters resources to permit only resources from a specific list
 * of servers.  Note that the parent workgroup names may need to be specified
 * (if users need to browse down to the server level from the parent).
 * This can be used in combination with a <code>NotFilter</code> to exclude a
 * specific set of servers.
 * <p>
 * This filter accepts a "servers" property, containing a whitespace-separated
 * list of server/workgroup names.  The "acceptRoot" property indicates
 * whether this filter should accept the "<code>smb://</code>" resource.
 * Note that if "acceptRoot" is set to "false", the SMB root will not be
 * browseable; inversely, if a <code>NotFilter</code> is applied, the
 * SMB root will <b>only</b> be accessible if "acceptRoot" is set to "false".
 *
 * @author Eric Glass
 */ 
public class ServerFilter implements DavenportFileFilter {

    private Set servers;

    private boolean acceptRoot;

    public void init(Properties properties) throws Exception {
        String acceptRoot = properties.getProperty("acceptRoot");
        this.acceptRoot = (acceptRoot == null) ? true :
                Boolean.valueOf(acceptRoot).booleanValue();
        Log.log(Log.DEBUG, this.acceptRoot ? "Accepting root." :
                "Rejecting root.");
        String servers = properties.getProperty("servers");
        if (servers == null) return;
        Set serverSet = new HashSet();
        StringTokenizer tokenizer = new StringTokenizer(servers);
        while (tokenizer.hasMoreTokens()) {
            serverSet.add(tokenizer.nextToken().toUpperCase());
        }
        Log.log(Log.DEBUG, "Accepting servers:\n{0}", serverSet);
        this.servers = serverSet;
    }

    public void destroy() {
        servers = null;
    }

    public boolean accept(SmbFile file) throws SmbException {
        String server = file.getServer();
        if (server == null) {
            Log.log(Log.DEBUG, "Is root; {0}", acceptRoot ? "accepting" :
                    "rejecting");
            return acceptRoot;
        }
        boolean status = servers.contains(server.toUpperCase());
        Log.log(Log.DEBUG, status ? "Server \"{0}\" is listed; accepting" :
                "Server \"{0}\" is not listed; rejecting", server);
        return status;
    }

}
