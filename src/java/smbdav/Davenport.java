/* Davenport WebDAV SMB Gateway
 * Copyright (C) 2003  Eric Glass
 * Copyright (C) 2003  Ronald Tschalär
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

import java.net.UnknownHostException;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.UnavailableException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jcifs.Config;
import jcifs.UniAddress;

import jcifs.http.NtlmSsp;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbSession;

import jcifs.util.Base64;

/**
 * This servlet provides a WebDAV gateway to CIFS/SMB shared resources.
 * This servlet provides WebDAV "Level 1" services; locking, etc. are not
 * supported.
 * <p>
 * You can specify jCIFS configuration settings in the servlet's
 * initialization parameters which will be applied to the environment.
 * Settings of particular interest to the Davenport servlet include:
 * <p>
 * <table border="1">
 * <tr>
 *     <th>Parameter</th><th>Description</th>
 * </tr>
 * <tr>
 *     <td><code>jcifs.smb.client.domain</code></td>
 *     <td>Provides the default domain if not specified during HTTP
 *     Basic authentication.  If the user enters "username" rather
 *     than "DOMAIN&#92;username", this specifies the default domain against
 *     which the user should be authenticated.</td>
 * </tr>
 * <tr>
 *     <td><code>jcifs.http.domainController</code></td>
 *     <td>Provides the IP address or name of the server used to authenticate
 *     clients.  This is only used for browsing the root
 *     ("<code>smb://</code>") and workgroups (if a server cannot be found).
 *     For servers, shares, directories and files, the corresponding server
 *     is used.  If not specified, the system will attempt to locate a
 *     controller for the domain specified in
 *     <code>jcifs.smb.client.domain</code> (if present).  <b>If neither
 *     <code>jcifs.http.domainController</code> nor
 *     <code>jcifs.smb.client.domain</code> are specified, authentication
 *     will not be required for browsing the SMB root (or workgroups for
 *     which a server cannot be found).</b>  This may pose a security
 *     risk.
 *     <p>
 *     It is not necessary for this to specify a real domain controller;
 *     any machine offering SMB services can be used.</td>
 * </tr>
 * <tr>
 *     <td><code>jcifs.http.enableBasic</code></td>
 *     <td>Enables/disables HTTP Basic authentication support.  This
 *     allows non-NTLM-capable browsers to successfully authenticate.
 *     NTLM-capable clients will authenticate using NTLM.  This defaults
 *     to <code>true</code>.  Setting this to <code>false</code> will
 *     disable HTTP Basic authentication entirely, allowing only
 *     NTLM-capable browsers to connect.</td>
 * </tr>
 * <tr>
 *     <td><code>jcifs.http.insecureBasic</code></td>
 *     <td>Enables/disables HTTP Basic authentication over an insecure
 *     channel.  Normally, HTTP Basic authentication will only be
 *     available over HTTPS.  Setting this to <code>true</code>
 *     will offer HTTP Basic authentication over insecure HTTP,
 *     sending login information over the network unencrypted.
 *     <b>This is a severe security risk, and is strongly advised against.</b>
 *     This defaults to <code>false</code>.</td>
 * </tr>
 * <tr>
 *     <td><code>jcifs.http.basicRealm</code></td>
 *     <td>Specifies the HTTP Basic realm that will be presented during
 *     authentication.  Defaults to "Davenport".</td>
 * </tr>
 * </table>
 * <p>
 * Further details regarding configuration of the jCIFS environment can be
 * found in the jCIFS documentation (available from
 * <a href="http://jcifs.samba.org">http://jcifs.samba.org</a>).
 * </p>
 * <p>
 * Additionally, you can specify your own custom handlers for HTTP methods.
 * By implementing {@link smbdav.MethodHandler}, you can provide your own
 * behavior for GET, PUT, etc. requests.  To enable your handler,
 * add an initialization parameter with the handler's classname.  For
 * example:
 * </p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;handler.GET&lt;/param-name&gt;
 *     &lt;param-value&gt;com.foo.MyGetHandler&lt;/param-value&gt;
 * &lt;/init-param&gt;
 * </pre>
 * <p>
 * This will install a <code>com.foo.MyGetHandler</code> instance as
 * the handler for GET requests.
 * </p>
 *
 * @author Eric Glass
 */
public class Davenport extends HttpServlet {

    private final Map handlers = new HashMap();

    private UniAddress defaultServer;

    private String defaultDomain;

    private String realm;

    private boolean alwaysAuthenticate;

    private boolean enableBasic;

    private boolean insecureBasic;

    public void init() throws ServletException {
        ServletConfig config = getServletConfig();
        String alwaysAuthenticate =
                config.getInitParameter("alwaysAuthenticate");
        this.alwaysAuthenticate =
                Boolean.valueOf(alwaysAuthenticate).booleanValue();
        Config.setProperty("jcifs.netbios.cachePolicy", "600");
        Config.setProperty("jcifs.smb.client.attrExpirationPeriod", "120000");
        Enumeration enumeration = config.getInitParameterNames();
        while (enumeration.hasMoreElements()) {
            String name = (String) enumeration.nextElement();
            if (name.startsWith("jcifs.")) {
                Config.setProperty(name, config.getInitParameter(name));
            }
        }
        String defaultDomain = Config.getProperty("jcifs.smb.client.domain");
        String defaultServer = Config.getProperty(
                "jcifs.http.domainController");
        if (defaultServer == null) defaultServer = defaultDomain;
        if (defaultServer != null) {
            try {
                this.defaultServer = UniAddress.getByName(defaultServer, true);
            } catch (UnknownHostException ex) {
                throw new UnavailableException(
                        "Default server could not be located.");
            }
        }
        String enableBasic = Config.getProperty("jcifs.http.enableBasic");
        this.enableBasic = (enableBasic == null) ||
                Boolean.valueOf(enableBasic).booleanValue();
        this.insecureBasic = Boolean.valueOf(
                Config.getProperty("jcifs.http.insecureBasic")).booleanValue();
        realm = Config.getProperty("jcifs.http.basicRealm");
        if (realm == null) realm = "Davenport";
        initHandlers(getServletConfig());
    }

    public void destroy() {
        Iterator iterator = handlers.entrySet().iterator();
        while (iterator.hasNext()) {
            ((MethodHandler) ((Map.Entry)
                    iterator.next()).getValue()).destroy();
            iterator.remove();
        }
    }

    /**
     * Authenticates the user against a domain before forwarding the
     * request to the appropriate handler.
     *
     * @param request The request being handled.
     * @param response The response supplied by the servlet.
     * @throws IOException If an IO error occurs while handling the request.
     * @throws ServletException If an application error occurs.
     */
    protected void service (HttpServletRequest request,
            HttpServletResponse response) throws IOException, ServletException {
        boolean usingBasic = enableBasic &&
                (insecureBasic || request.isSecure());
        String pathInfo = request.getPathInfo();
        if (pathInfo == null || "".equals(pathInfo)) pathInfo = "/";
        String target = "smb:/" + pathInfo;
        UniAddress server = null;
        try {
            server = getServer(target);
        } catch (UnknownHostException ex) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND,
                    "Unable to identify or locate \"" + target + "\".");
            return;
        }
        NtlmPasswordAuthentication authentication = null;
        String authorization = request.getHeader("Authorization");
        if (authorization != null &&
                authorization.regionMatches(true, 0, "NTLM ", 0, 5)) {
            byte[] challenge = SmbSession.getChallenge(server);
            authentication = NtlmSsp.authenticate(request, response, challenge);
            if (authentication == null) return;
        } else if (authorization != null && usingBasic &&
                authorization.regionMatches(true, 0, "Basic ", 0, 6)) {
            String authInfo = new String(
                    Base64.decode(authorization.substring(6)), "ISO-8859-1");
            int index = authInfo.indexOf(':');
            String user = (index != -1) ?
                    authInfo.substring(0, authInfo.indexOf(':')) : authInfo;
            String domain;
            if (user.indexOf('\\') != -1) {
                domain = user.substring(0, user.indexOf('\\'));
                user = user.substring(user.indexOf('\\') + 1);
            } else if (user.indexOf('/') != -1) {
                domain = user.substring(0, user.indexOf('/'));
                user = user.substring(user.indexOf('/') + 1);
            } else {
                domain = defaultDomain;
            }
            String password = (index != -1) ?
                    authInfo.substring(authInfo.indexOf(':') + 1) : null;
            authentication = new NtlmPasswordAuthentication(domain, user,
                    password);
            try {
                SmbSession.logon(server, authentication);
            } catch (SmbAuthException ex) {
                response.setHeader("WWW-Authenticate", "NTLM");
                response.addHeader("WWW-Authenticate", "Basic realm=\"" +
                        realm + "\"");
                response.setHeader("Connection", "close");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.flushBuffer();
                return;
            }
        } else if (alwaysAuthenticate && server != null) {
            response.setHeader("WWW-Authenticate", "NTLM");
            if (usingBasic) {
                response.addHeader("WWW-Authenticate", "Basic realm=\"" +
                        realm + "\"");
            }
            response.setHeader("Connection", "close");
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.flushBuffer();
            return;
        }
        MethodHandler handler = getHandler(request.getMethod());
        if (handler != null) {
            try {
                handler.service(request, response, authentication);
            } catch (SmbAuthException ex) {
                try {
                    response.reset();
                } catch (IllegalStateException ignore) { }
                response.setHeader("WWW-Authenticate", "NTLM");
                if (usingBasic) {
                    response.addHeader("WWW-Authenticate", "Basic realm=\"" +
                            realm + "\"");
                }
                response.setHeader("Connection", "close");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.flushBuffer();
                return;
            }
        } else {
            response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        }
    }

    /**
     * Returns the <code>MethodHandler</code> for the specified method.
     *
     * @param method The HTTP method (GET, POST, PUT, etc.) being handled.
     * @return A <code>MethodHandler</code> capable of servicing the request
     * using the given method.
     */
    protected MethodHandler getHandler(String method) {
        if (method == null) return null;
        return (MethodHandler) handlers.get(method.toUpperCase());
    }

    private void initHandlers(ServletConfig config) throws ServletException {
        handlers.clear();
        handlers.put("OPTIONS", new DefaultOptionsHandler());
        handlers.put("HEAD", new DefaultHeadHandler());
        handlers.put("GET", new DefaultGetHandler());
        handlers.put("POST", new DefaultPostHandler());
        handlers.put("DELETE", new DefaultDeleteHandler());
        handlers.put("PROPFIND", new DefaultPropfindHandler());
        handlers.put("PROPPATCH", new DefaultProppatchHandler());
        handlers.put("COPY", new DefaultCopyHandler());
        handlers.put("MOVE", new DefaultMoveHandler());
        handlers.put("PUT", new DefaultPutHandler());
        handlers.put("MKCOL", new DefaultMkcolHandler());
        Enumeration parameters = config.getInitParameterNames();
        while (parameters.hasMoreElements()) {
            String name = (String) parameters.nextElement();
            if (!name.startsWith("handler.")) continue;
            String method = name.substring(8);
            try {
                handlers.put(method.toUpperCase(), Class.forName(
                        config.getInitParameter(name)).newInstance());
            } catch (Exception ex) {
                throw new UnavailableException("Could not create handler for " +
                        method + " method: " + ex);
            }
        }
        Iterator iterator = handlers.values().iterator();
        while (iterator.hasNext()) {
            ((MethodHandler) iterator.next()).init(config);
        }
    }

    private UniAddress getServer(String target) throws IOException {
        try {
            SmbFile file = new SmbFile(target);
            String host = file.getServer();
            if (host == null) return defaultServer;
            file = new SmbFile(file, "/");
            try {
                return UniAddress.getByName(host,
                        (file.getType() == SmbFile.TYPE_WORKGROUP));
            } catch (UnknownHostException ex) {
                return defaultServer;
            }
        } catch (IOException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IOException("Unable to get authentication server: " + ex);
        }
    }

}
