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

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;

import java.net.URL;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.UnavailableException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import javax.xml.transform.Source;
import javax.xml.transform.Templates;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerException;

import javax.xml.transform.dom.DOMSource;

import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbAuthException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileInputStream;

import org.w3c.dom.Document;

/**
 * Default implementation of a handler for requests using the HTTP GET
 * method.
 * <p>
 * In addition to providing standard GET functionality for resources,
 * this implementation provides directory listings for collections.
 * An XSL stylesheet can be specified to customize the appearance of
 * the listing.  The default stylesheet location is provided in the Davenport
 * servlet's deployment descriptor as the "directory.xsl" initialization
 * parameter, i.e.:
 * <p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;directory.xsl&lt;/param-name&gt;
 *     &lt;param-value&gt;/mydir.xsl&lt;/param-value&gt;
 * &lt;/init-param&gt;
 * </pre>
 * <p>
 * The stylesheet location is resolved as follows:
 * <ul>
 * <li>
 * First, the system will look for the stylesheet as a servlet context resource
 * (via <code>ServletContext.getResourceAsStream()</code>).
 * </li>
 * <li>
 * Next, the system will attempt to load the stylesheet as a classloader
 * resource (via <code>ClassLoader.getResourceAsStream()</code>), using the
 * Davenport classloader, the thread context classloader, and the system
 * classloader (in that order).
 * </li>
 * <li>
 * Finally, the system will attempt to load the stylesheet directly.
 * This will only succeed if the location is specified as an absolute URL.
 * </li>
 * </ul>
 * <p>
 * If not specified, this is set to "<code>/META-INF/directory.xsl</code>",
 * which will load a default stylesheet from the Davenport jarfile.
 * <p>
 * Users can also configure their own directory stylesheets.  The
 * configuration page can be accessed by pointing your web browser
 * at any Davenport collection resource and passing "configure" as
 * a URL parameter:
 * </p>
 * <p>
 * <code>http://server/davenport/any/?configure</code>
 * </p>
 * <p>
 * The configuration page can be specified in the deployment descriptor
 * via the "directory.configuration" initialization parameter, i.e.:
 * <p>
 * <pre>
 * &lt;init-param&gt;
 *     &lt;param-name&gt;directory.configuration&lt;/param-name&gt;
 *     &lt;param-value&gt;/configuration.html&lt;/param-value&gt;
 * &lt;/init-param&gt;
 * </pre>
 * <p>
 * The configuration page's location is resolved in the same manner as the
 * default stylesheet described above.
 * <p>
 * If not specified, this is set to "<code>/META-INF/configuration.html</code>",
 * which will load and cache a default configuration page from the
 * Davenport jarfile.
 * <p>
 * 
 * @author Eric Glass
 */
public class DefaultGetHandler extends AbstractHandler {

    private Templates defaultTemplates;

    private PropertiesBuilder propertiesBuilder;

    private byte[] configuration;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        propertiesBuilder = new DefaultPropertiesBuilder();
        propertiesBuilder.init(config);
        try {
            String stylesheet = config.getInitParameter("directory.xsl");
            if (stylesheet == null) stylesheet = "/META-INF/directory.xsl";
            Source source = getStylesheet(stylesheet, true);
            defaultTemplates = TransformerFactory.newInstance().newTemplates(
                    source);
        } catch (Exception ex) {
            throw new UnavailableException(
                    "Unable to load directory stylesheet: " + ex);
        }
        String configuration =
                config.getInitParameter("directory.configuration");
        if (configuration == null) {
            configuration = "/META-INF/configuration.html";
        }
        InputStream stream = getResourceAsStream(configuration);
        try {
            if (stream == null) stream = new URL(configuration).openStream();
            ByteArrayOutputStream collector = new ByteArrayOutputStream();
            byte[] buffer = new byte[2048];
            int count;
            while ((count = stream.read(buffer, 0, 2048)) != -1) {
                collector.write(buffer, 0, count);
            }
            this.configuration = collector.toByteArray();
        } catch (Exception ex) {
            throw new UnavailableException(
                    "Unable to load configuration page: " + ex);
        }
    }

    public void destroy() {
        propertiesBuilder.destroy();
        propertiesBuilder = null;
        defaultTemplates = null;
        super.destroy();
    }

    /**
     * Services requests which use the HTTP GET method.
     * This implementation retrieves the content for non-collection resources,
     * using the content type information mapped in
     * {@link smbdav.SmbDAVUtilities}.  For collection resources, the
     * collection listing is retrieved as from a PROPFIND request with
     * a depth of 1 (the collection and its immediate contents).  The
     * directory listing stylesheet is applied to the resultant XML
     * document.
     * <br>
     * If the specified file does not exist, a 404 (Not Found) error is
     * sent to the client.
     * <br>
     * If the user does not have sufficient privileges to perform the
     * operation, a 401 (Unauthorized) error is sent to the client.
     * <br>
     *
     * @param request The request being serviced.
     * @param response The servlet response.
     * @param auth The user's authentication information.
     * @throws ServletException If an application error occurs.
     * @throws IOException If an IO error occurs while handling the request.
     *
     */
    public void service(HttpServletRequest request,
            HttpServletResponse response, NtlmPasswordAuthentication auth)
                    throws ServletException, IOException {
        SmbFile file = getSmbFile(request, auth);
        if (!file.exists()) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }
        if (file.getName().endsWith("/") &&
                !request.getRequestURL().toString().endsWith("/")) {
            StringBuffer redirect = request.getRequestURL().append("/");
            String query = request.getQueryString();
            if (query != null) redirect.append("?").append(query);
            response.sendRedirect(redirect.toString());
            return;
        }
        if (!file.isFile()) {
            if ("configure".equals(request.getQueryString())) {
                showConfiguration(request, response);
                return;
            }
            String view = request.getParameter("view");
            if (view == null) {
                Cookie[] cookies = request.getCookies();
                if (cookies != null) {
                    for (int i = cookies.length - 1; i >= 0; i--) {
                        if (cookies[i].getName().equals("view")) {
                            view = cookies[i].getValue();
                            break;
                        }
                    }
                }
            } else {
                view = view.trim();
                Cookie cookie = new Cookie("view", view);
                if (view.equals("")) {
                    view = null;
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        session.removeAttribute("davenport.templates");
                    }
                    cookie.setMaxAge(0);
                } else {
                    cookie.setMaxAge(Integer.MAX_VALUE);
                }
                response.addCookie(cookie);
            }
            Templates templates = defaultTemplates;
            if (view != null) {
                templates = null;
                try {
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        templates = (Templates)
                                session.getAttribute("davenport.templates");
                    }
                    if (templates == null) {
                        Source source = getStylesheet(view, false);
                        templates = TransformerFactory.newInstance(
                                ).newTemplates(source);
                        if (session != null) {
                            session.setAttribute("davenport.templates",
                                    templates);
                        }
                    }
                } catch (Exception ex) {
                    HttpSession session = request.getSession(false);
                    if (session != null) {
                        session.removeAttribute("davenport.templates");
                    }
                    showConfiguration(request, response);
                    return;
                }
            }
            PropertiesDirector director = new PropertiesDirector(
                    getPropertiesBuilder());
            String href = request.getRequestURL().toString();
            Document properties = null;
            try {
                properties = director.getAllProperties(file, href, 1);
            } catch (SmbAuthException ex) {
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Unable to access directory listing for " + file);
                return;
            }
            try {
                Transformer transformer = templates.newTransformer();
                transformer.setParameter("href", href);
                transformer.setParameter("url", file.toString());
                transformer.setParameter("unc", file.getUncPath());
                String type;
                switch (file.getType()) {
                case SmbFile.TYPE_WORKGROUP:
                    type = "TYPE_WORKGROUP";
                    break;
                case SmbFile.TYPE_SERVER:
                    type = "TYPE_SERVER";
                    break;
                case SmbFile.TYPE_SHARE:
                    type = "TYPE_SHARE";
                    break;
                case SmbFile.TYPE_FILESYSTEM:
                    type = "TYPE_FILESYSTEM";
                    break;
                case SmbFile.TYPE_PRINTER:
                    type = "TYPE_PRINTER";
                    break;
                case SmbFile.TYPE_NAMED_PIPE:
                    type = "TYPE_NAMED_PIPE";
                    break;
                case SmbFile.TYPE_COMM:
                    type = "TYPE_COMM";
                    break;
                default:
                    type = "TYPE_UNKNOWN";
                }
                transformer.setParameter("type", type);
                transformer.setOutputProperty("encoding", "UTF-8");
                ByteArrayOutputStream collector = new ByteArrayOutputStream();
                transformer.transform(new DOMSource(properties),
                        new StreamResult(collector));
                response.setContentType("text/html; charset=\"utf-8\"");
                response.getOutputStream().write(collector.toByteArray());
                response.flushBuffer();
            } catch (TransformerException ex) {
                throw new IOException(ex.getMessage());
            }
            return;
        }
        String etag = SmbDAVUtilities.getETag(file);
        if (etag != null) response.setHeader("ETag", etag);
        response.setHeader("Last-Modified",
                SmbDAVUtilities.formatGetLastModified(file.lastModified()));
        int result = checkConditionalRequest(request, file);
        if (result != HttpServletResponse.SC_OK) {
            response.setStatus(result);
            response.setContentLength(0);
            response.flushBuffer();
            return;
        }
        String contentType = getServletConfig().getServletContext().getMimeType(
                file.getName());
        response.setContentType((contentType != null) ? contentType :
                "application/octet-stream");
        response.setContentLength((int) file.length());
        SmbFileInputStream input = new SmbFileInputStream(file);
        ServletOutputStream output = response.getOutputStream();
        byte[] buf = new byte[8192];
        int count;
        while ((count = input.read(buf)) != -1) {
            output.write(buf, 0, count);
        }
        output.flush();
        input.close();
    }

    /**
     * Returns the <code>PropertiesBuilder</code> that will be used
     * to build the PROPFIND result XML document for directory listings.
     *
     * @return The <code>PropertiesBuilder</code> used to build the
     * XML document.
     */
    protected PropertiesBuilder getPropertiesBuilder() {
        return propertiesBuilder;
    }

    private void showConfiguration(HttpServletRequest request,
            HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");
        OutputStream output = response.getOutputStream();
        output.write(configuration);
        response.flushBuffer();
    }

    private InputStream getResourceAsStream(String location) {
        InputStream stream = null;
        try {
            stream = getServletConfig().getServletContext(
                    ).getResourceAsStream(location);
            if (stream != null) return stream;
        } catch (Exception ex) { }
        try {
            stream = getClass().getResourceAsStream(location);
            if (stream != null) return stream;
        } catch (Exception ex) { }
        try {
            ClassLoader loader = Thread.currentThread(
                    ).getContextClassLoader();
            if (loader != null) stream = loader.getResourceAsStream(location);
            if (stream != null) return stream;
        } catch (Exception ex) { }
        try {
            ClassLoader loader = ClassLoader.getSystemClassLoader();
            if (loader != null) stream = loader.getResourceAsStream(location);
            if (stream != null) return stream;
        } catch (Exception ex) { }
        return null;
    }

    private Source getStylesheet(String location, boolean allowExternal)
            throws Exception {
        InputStream stream = getResourceAsStream(location);
        if (stream != null) return new StreamSource(stream);
        if (!allowExternal) {
            throw new IllegalArgumentException("Stylesheet not found.");
        }
        return new StreamSource(location);
    }

}
