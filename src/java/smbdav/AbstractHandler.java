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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.StringTokenizer;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import jcifs.smb.SmbFileFilter;

/**
 * An abstract implementation of the <code>MethodHandler</code> interface.
 * This class serves as a convenient basis for building method handlers.
 * In addition to providing basic <code>init</code> and <code>destroy</code>
 * methods, several useful utility methods are supplied.
 * 
 * @author Eric Glass
 */
public abstract class AbstractHandler implements MethodHandler {

    private static final Set KNOWN_WORKGROUPS =
            Collections.synchronizedSet(new HashSet());

    private ServletConfig config;

    /**
     * Initializes the method handler.  This implementation stores the
     * provided <code>ServletConfig</code> object and makes it available
     * via the <code>getServletConfig</code> method.  Subclasses overriding
     * this method should start by invoking
     * <p>
     * <code>super.init(config);</code>
     *
     * @param config a <code>ServletConfig</code> object containing
     * the servlet's configuration and initialization parameters.
     * @throws ServletException If an error occurs during initialization.
     */
    public void init(ServletConfig config) throws ServletException {
        this.config = config;
    }

    public void destroy() {
        config = null;
    }

    /**
     * Returns the <code>ServletConfig</code> object that was provided to the
     * <code>init</code> method.
     *
     * @return A <code>ServletConfig</code> object containing the servlet's
     * configuration and initialization parameters.
     */
    protected ServletConfig getServletConfig() {
        return config;
    }

    /**
     * Returns the charset used to interpret request URIs.  Davenport will
     * attempt to use this charset before resorting to UTF-8.
     *
     * @return A <code>String</code> containing the charset name.
     */
    protected String getRequestURICharset() {
        ServletConfig config = getServletConfig();
        String charset = (config == null) ? null : (String)
                config.getServletContext().getAttribute(
                        Davenport.REQUEST_URI_CHARSET);
        return (charset != null) ? charset : "ISO-8859-1";
    }

    /**
     * Rewrites the supplied HTTP URL against the active context base if
     * necessary.
     *
     * @param request The request being serviced.
     * @param url The HTTP URL to process for rewriting.
     * @return A <code>String</code> containing the rewritten URL.  If
     * no rewriting is required, the provided URL will be returned.
     */
    protected String rewriteURL(HttpServletRequest request, String url) {
        String contextBase = (String)
                request.getAttribute(Davenport.CONTEXT_BASE);
        if (contextBase == null || url.startsWith(contextBase)) return url;
        String base = request.getContextPath() + request.getServletPath();
        int index = url.indexOf(base);
        if (index == -1) return url;
        Log.log(Log.INFORMATION,
                "Rewriting URL \"{0}\" against context base \"{1}\".",
                        new Object[] { url, contextBase });
        url = url.substring(index);
        if (!contextBase.endsWith("/")) contextBase += "/";
        if (url.startsWith("/")) url = url.substring(1);
        url = contextBase + url;
        Log.log(Log.INFORMATION, "Rewrote URL to \"{0}\".", url);
        return url;
    }

    /**
     * Convenience method to return the HTTP URL from the request, rewritten
     * against the active context base as necessary.
     *
     * @param request The request being serviced.
     * @return A <code>String</code> containing the rewritten request URL.
     */ 
    protected String getRequestURL(HttpServletRequest request) {
        return rewriteURL(request, request.getRequestURL().toString());
    }

    /**
     * Convenience method to convert a given HTTP URL to the corresponding
     * SMB URL.  The provided request is used to determine the servlet base;
     * this is stripped from the given HTTP URL to get the SMB path.
     * Escaped characters within the specified HTTP URL are interpreted
     * as members of the character set returned by
     * <code>getRequestURICharset()</code>.
     * <b>Note:</b> Currently, the jCIFS library does not handle escaped
     * characters in SMB URLs (i.e.,
     * "<code>smb://server/share/my%20file.txt</code>".  The SMB URLs
     * returned by this method are unescaped for compatibility with jCIFS
     * (i.e., "<code>smb://server/share/my file.txt</code>".  This may result
     * in URLs which do not conform with RFC 2396.  Such URLs may not be
     * accepted by systems expecting compliant URLs (such as Java 1.4's
     * <code>java.net.URI</code> class).
     *
     * @param request The servlet request upon which the HTTP URL is based.
     * @param httpUrl An HTTP URL from which the SMB URL is derived.
     * @throws IOException If an SMB URL cannot be constructed from the
     * given request and HTTP URL.
     */
    protected String getSmbURL(HttpServletRequest request, String httpUrl)
            throws IOException {
        return getSmbURL(request, httpUrl, getRequestURICharset());
    }

    /**
     * Convenience method to convert a given HTTP URL to the corresponding
     * SMB URL.  The provided request is used to determine the servlet base;
     * this is stripped from the given HTTP URL to get the SMB path.
     * Escaped characters within the specified HTTP URL are interpreted
     * as members of the given character set.
     * <b>Note:</b> Currently, the jCIFS library does not handle escaped
     * characters in SMB URLs (i.e.,
     * "<code>smb://server/share/my%20file.txt</code>".  The SMB URLs
     * returned by this method are unescaped for compatibility with jCIFS
     * (i.e., "<code>smb://server/share/my file.txt</code>".  This may result
     * in URLs which do not conform with RFC 2396.  Such URLs may not be
     * accepted by systems expecting compliant URLs (such as Java 1.4's
     * <code>java.net.URI</code> class).
     *
     * @param request The servlet request upon which the HTTP URL is based.
     * @param httpUrl An HTTP URL from which the SMB URL is derived.
     * @param charset The character set that should be used to interpret the
     * HTTP URL.
     * @throws IOException If an SMB URL cannot be constructed from the
     * given request and HTTP URL.
     */
    protected String getSmbURL(HttpServletRequest request, String httpUrl,
            String charset) throws IOException {
        Log.log(Log.DEBUG, "Converting \"{0}\" to an SMB URL " +
                "using charset \"{1}\".", new Object[] { httpUrl, charset });
        if (httpUrl == null) return null;
        httpUrl = rewriteURL(request, httpUrl);
        String base = request.getContextPath() + request.getServletPath();
        int index = httpUrl.indexOf(base);
        if (index == -1) {
            Log.log(Log.DEBUG, "Specified URL is not under this context.");
            return null;
        }
        index += base.length();
        httpUrl = (index < httpUrl.length()) ?
                httpUrl.substring(index) : "/";
        SmbFile file = new SmbFile("smb:/" + unescape(httpUrl, charset));
        String server = file.getServer();
        base = file.getCanonicalPath();
        if (server != null && KNOWN_WORKGROUPS.contains(server.toUpperCase())) {
            Log.log(Log.DEBUG, "Target \"{0}\" is a known workgroup.", server);
            index = base.indexOf(server);
            int end = index + server.length();
            if (end < base.length() && base.charAt(end) == '/') end++;
            if (end < base.length()) {
                base = new StringBuffer(base).delete(index, end).toString();
            }
        }
        Log.log(Log.DEBUG, "Converted to SMB URL \"{0}\".", base);
        return base;
    }

    /**
     * Returns the <code>SmbFileFilter</code> used to filter resource
     * requests.  The default implementation uses the global filter
     * installed by the Davenport servlet (if applicable).
     *
     * @return The filter to be applied to requested resources.  Returns
     * <code>null</code> if no filter is to be applied.
     */ 
    protected SmbFileFilter getFilter() {
        ServletConfig config = getServletConfig();
        return (config == null) ? null : (SmbFileFilter)
                config.getServletContext().getAttribute(
                        Davenport.RESOURCE_FILTER);
    }

    /**
     * Convenience method to retrieve the <code>SmbFile</code> that
     * is the target of the given request.  This will attempt to obtain
     * the file by interpreting the URL with the character set given by
     * <code>getRequestURICharset()</code>; if this file does not exist, a
     * second attempt will be made using the UTF-8 charset.  If neither file
     * exists, the result of the first attempt will be returned.
     * 
     * @param request The request that is being serviced.
     * @param auth The user's authentication information.
     * @throws IOException If the <code>SmbFile</code> targeted by
     * the specified request could not be created.
     */
    protected SmbFile getSmbFile(HttpServletRequest request,
            NtlmPasswordAuthentication auth) throws IOException {
        String url = getRequestURL(request);
        SmbFile file = null;
        IOException exception = null;
        boolean exists = false;
        String charset = getRequestURICharset();
        try {
            file = createSmbFile(getSmbURL(request, url, charset), auth);
            exists = file.exists();
        } catch (IOException ex) {
            exception = ex;
        }
        if (exists) return file;
        if (charset.equals("UTF-8")) {
            if (exception != null) {
                Log.log(Log.DEBUG, exception);
                throw exception;
            }
            return file;
        }
        SmbFile utf8 = null;
        IOException utf8Exception = null;
        try {
            utf8 = createSmbFile(getSmbURL(request, url, "UTF-8"), auth);
            exists = utf8.exists();
        } catch (IOException ex) {
            utf8Exception = ex;
        }
        if (exists) return utf8;
        if (file != null) {
            if (exception != null) {
                Log.log(Log.DEBUG, exception);
                throw exception;
            }
            return file;
        }
        if (utf8 != null) {
            if (utf8Exception != null) {
                Log.log(Log.DEBUG, exception);
                throw utf8Exception;
            }
            return utf8;
        }
        if (exception != null) {
            Log.log(Log.DEBUG, exception);
            throw exception;
        }
        Log.log(Log.WARNING, "Returning null SmbFile (shouldn't happen).");
        return null;
    }

    /**
     * Convenience method to create an <code>SmbFile</code> object
     * from a specified SMB URL and authentication information.
     * The <code>SmbFile</code> returned will automatically be adjusted
     * to include a trailing slash ("/") in the event that it refers to a
     * directory, share, server, or workgroup.
     *
     * @param smbUrl The SMB URL from which the <code>SmbFile</code> object
     * will be created.
     * @param authentication The authentication information to apply to the
     * <code>SmbFile</code> object.
     * @throws IOException If an <code>SmbFile</code> object could not be
     * created from the provided information.
     */
    protected SmbFile createSmbFile(String smbUrl,
            NtlmPasswordAuthentication authentication) throws IOException {
        try {
            Log.log(Log.DEBUG,
                    "Creating SMB file for \"{0}\" with credentials \"{1}\".",
                            new Object[] { smbUrl, authentication });
            SmbFile smbFile = (authentication != null) ?
                    new SmbFile(smbUrl, authentication) : new SmbFile(smbUrl);
            if (!smbUrl.endsWith("/") && needsSeparator(smbFile)) {
                smbUrl += "/";
                smbFile = (authentication != null) ?
                        new SmbFile(smbUrl, authentication) :
                                new SmbFile(smbUrl);
            }
            if (smbFile.getType() == SmbFile.TYPE_WORKGROUP) {
                String server = smbFile.getServer();
                if (server != null) {
                    Log.log(Log.INFORMATION,
                            "Adding \"{0}\" to the set of known workgroups.",
                                    server);
                    KNOWN_WORKGROUPS.add(server.toUpperCase());
                }
            }
            SmbFileFilter filter = getFilter();
            if (filter != null && !filter.accept(smbFile)) {
                Log.log(Log.INFORMATION, "Filter blocked access to \"{0}\".",
                        smbFile);
                smbFile = new BlockedFile(smbFile);
            }
            Log.log(Log.DEBUG, "Created SMB file \"{0}\".", smbFile);
            return smbFile;
        } catch (SmbException ex) {
            Log.log(Log.DEBUG, ex);
            throw ex;
        } catch (Exception ex) {
            String message = SmbDAVUtilities.getResource(AbstractHandler.class,
                    "cantCreateSmbFile", new Object[] { ex }, null);
            Log.log(Log.DEBUG, message + "\n{0}", ex);
            throw new IOException(message);
        }
    }

    /**
     * Checks if a conditional request should apply.  If the client specifies
     * one or more conditional cache headers ("<code>If-Match</code>",
     * "<code>If-None-Match</code>", "<code>If-Modified-Since</code>", or
     * "<code>If-Unmodified-Since" -- "<code>If-Range</code>" is not
     * currently supported), this method will indicate whether the
     * request should be processed.
     *
     * @param request The servlet request whose conditional cache headers
     * will be examined.
     * @param file The resource that is being examined.
     * @return An HTTP status code indicating the result.  This will be one of:
     * <ul>
     * <li><code>200</code> (<code>HttpServletResponse.SC_OK</code>) --
     * if the request should be serviced normally</li>
     * <li><code>304</code> (<code>HttpServletResponse.SC_NOT_MODIFIED</code>)
     * -- if the resource has not been modified</li>
     * <li><code>412</code>
     * (<code>HttpServletResponse.SC_PRECONDITION_FAILED</code>) --
     * if no matching entity was found</li>
     * </ul>
     * @throws SmbException If an error occurs while examining the resource.
     */
    protected int checkConditionalRequest(HttpServletRequest request,
            SmbFile file) throws IOException {
        Enumeration values = request.getHeaders("If-None-Match");
        if (values.hasMoreElements()) {
            String etag = SmbDAVUtilities.getETag(file);
            if (etag != null) {
                boolean match = false;
                do {
                    String value = (String) values.nextElement();
                    if ("*".equals(value) || etag.equals(value)) match = true;
                } while (!match && values.hasMoreElements());
                if (match) {
                    long timestamp = request.getDateHeader("If-Modified-Since");
                    if (timestamp == -1 ||
                            timestamp >= (file.lastModified() / 1000 * 1000)) {
                        Log.log(Log.INFORMATION,
                                "Resource has not been modified.");
                        return HttpServletResponse.SC_NOT_MODIFIED;
                    }
                }
            }
        } else {
            values = request.getHeaders("If-Match");
            if (values.hasMoreElements()) {
                String etag = SmbDAVUtilities.getETag(file);
                if (etag == null) {
                    Log.log(Log.INFORMATION, "Precondition failed.");
                    return HttpServletResponse.SC_PRECONDITION_FAILED;
                }
                boolean match = false;
                do {
                    String value = (String) values.nextElement();
                    if ("*".equals(value) || etag.equals(value)) match = true;
                } while (!match && values.hasMoreElements());
                if (!match) {
                    Log.log(Log.INFORMATION, "Precondition failed.");
                    return HttpServletResponse.SC_PRECONDITION_FAILED;
                }
            }
            long timestamp = request.getDateHeader("If-Unmodified-Since");
            if (timestamp != -1) {
                if ((file.lastModified() / 1000 * 1000) > timestamp) {
                    Log.log(Log.INFORMATION, "Precondition failed.");
                    return HttpServletResponse.SC_PRECONDITION_FAILED;
                }
            } else {
                timestamp = request.getDateHeader("If-Modified-Since");
                if (timestamp != -1 &&
                        timestamp >= (file.lastModified() / 1000 * 1000)) {
                    Log.log(Log.INFORMATION, "Resource has not been modified.");
                    return HttpServletResponse.SC_NOT_MODIFIED;
                }
            }
        }
        return HttpServletResponse.SC_OK;
    }

    private boolean needsSeparator(SmbFile file) throws SmbException {
        if (file.getName().endsWith("/")) return true;
        int type = file.getType();
        if (type == SmbFile.TYPE_WORKGROUP || type == SmbFile.TYPE_SERVER ||
                type == SmbFile.TYPE_SHARE) {
            return true;
        }
        return (file.isDirectory());
    }

    private String unescape(String escaped, String charset) throws IOException {
        StringTokenizer tokenizer = new StringTokenizer(escaped, "%", true);
        StringBuffer buffer = new StringBuffer();
        ByteArrayOutputStream encoded = new ByteArrayOutputStream();
        while (tokenizer.hasMoreTokens()) {
            String token = tokenizer.nextToken();
            if (!"%".equals(token)) {
                buffer.append(token);
                continue;
            }
            while (tokenizer.hasMoreTokens() && token.equals("%")) {
                token = tokenizer.nextToken();
                encoded.write(Integer.parseInt(token.substring(0, 2), 16));
                token = token.substring(2);
                if ("".equals(token) && tokenizer.hasMoreTokens()) {
                    token = tokenizer.nextToken();
                }
            }
            buffer.append(encoded.toString(charset));
            encoded.reset();
            if (!token.equals("%")) buffer.append(token);
        }
        return buffer.toString();
    }

    public abstract void service(HttpServletRequest request,
            HttpServletResponse response, NtlmPasswordAuthentication auth)
                    throws IOException, ServletException;

}
