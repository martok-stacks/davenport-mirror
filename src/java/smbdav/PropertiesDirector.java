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

import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class directs a <code>PropertiesBuilder</code> in the creation
 * and retrieval of a PROPFIND result XML document.
 *
 * @author Eric Glass
 */
public class PropertiesDirector {

    private static final boolean[] ESCAPED;

    static {
        ESCAPED = new boolean[128];
        for (int i = 0; i < 128; i++) {
            ESCAPED[i] = true;
        }
        for (int i = 'A'; i <= 'Z'; i++) {
            ESCAPED[i] = false;
        }
        for (int i = 'a'; i <= 'z'; i++) {
            ESCAPED[i] = false;
        }
        for (int i = '0'; i <= '9'; i++) {
            ESCAPED[i] = false;
        }
        ESCAPED['+'] = false;
        ESCAPED['-'] = false;
        ESCAPED['='] = false;
        ESCAPED['.'] = false;
        ESCAPED['_'] = false;
        ESCAPED['*'] = false;
        ESCAPED['('] = false;
        ESCAPED[')'] = false;
        ESCAPED[','] = false;
        ESCAPED['@'] = false;
        ESCAPED['\''] = false;
        ESCAPED['$'] = false;
        ESCAPED[':'] = false;
        ESCAPED['&'] = false;
        ESCAPED['!'] = false;
    }

    private final PropertiesBuilder builder;

    /**
     * Creates a <code>PropertiesDirector</code> which uses the specified
     * builder to create the PROPFIND XML document.
     * 
     * @param builder The <code>PropertiesBuilder</code> used to
     * create the PROPFIND result XML document.
     */
    public PropertiesDirector(PropertiesBuilder builder) {
        this.builder = builder;
    }

    /**
     * Returns the PROPFIND result XML document for the specified resource
     * containing the names of all supported properties.
     *
     * @param file The resource whose property names are to be retrieved.
     * @param href The HTTP URL by which the resource was accessed.
     * @param depth The depth to which the request is applied.  <code>0</code>
     * specifies the resource only; <code>1</code> specifies the resource
     * and its immediate children; <code>INFINITY</code> specifies the
     * resource and all of its progeny.
     * @return An XML <code>Document</code> containing the PROPFIND result.
     * @throws IOException If an IO error occurs during the construction
     * of the document.
     */
    public Document getPropertyNames(SmbFile file, String href, int depth)
            throws IOException {
        Document document = getPropertiesBuilder().createDocument();
        addPropertyNames(document, file, href, depth);
        return document;
    }

    /**
     * Returns the PROPFIND result XML document for the specified resource
     * containing the names and values of all supported properties.
     *
     * @param file The resource whose properties are to be retrieved.
     * @param href The HTTP URL by which the resource was accessed.
     * @param depth The depth to which the request is applied.  <code>0</code>
     * specifies the resource only; <code>1</code> specifies the resource
     * and its immediate children; <code>INFINITY</code> specifies the
     * resource and all of its progeny.
     * @return An XML <code>Document</code> containing the PROPFIND result.
     * @throws IOException If an IO error occurs during the construction
     * of the document.
     */
    public Document getAllProperties(SmbFile file, String href, int depth)
            throws IOException {
        Document document = getPropertiesBuilder().createDocument();
        addAllProperties(document, file, href, depth);
        return document;
    }

    /**
     * Returns the PROPFIND result XML document for the specified resource
     * containing the values of the specifed properties.
     *
     * @param file The resource whose properties are to be retrieved.
     * @param href The HTTP URL by which the resource was accessed.
     * @param props The names of the properties which are to be retrieved.
     * @param depth The depth to which the request is applied.  <code>0</code>
     * specifies the resource only; <code>1</code> specifies the resource
     * and its immediate children; <code>INFINITY</code> specifies the
     * resource and all of its progeny.
     * @return An XML <code>Document</code> containing the PROPFIND result.
     * @throws IOException If an IO error occurs during the construction
     * of the document.
     */
    public Document getProperties(SmbFile file, String href, Element[] props,
            int depth) throws IOException {
        Document document= getPropertiesBuilder().createDocument();
        addProperties(document, file, href, props, depth);
        return document;
    }

    /**
     * Returns the builder used to construct the XML document.
     * 
     * @return The <code>PropertiesBuilder</code> object that will be used
     * to create the PROPFIND result XML document.
     */
    protected PropertiesBuilder getPropertiesBuilder() {
        return builder;
    }

    private void addPropertyNames(Document document, SmbFile file, String href,
            int depth) throws IOException {
        getPropertiesBuilder().addPropNames(document, file, href);
        if (depth > 0 && !file.isFile()) {
            SmbFile[] children = null;
            try {
                children = file.listFiles();
            } catch (SmbException ex) { }
            if (children == null) return;
            int count = children.length;
            if (count == 0) return;
            if (!href.endsWith("/")) href += "/";
            --depth;
            if (file.getType() == SmbFile.TYPE_WORKGROUP &&
                    !"smb://".equals(file.toString())) {
                int index = href.lastIndexOf(file.getName());
                if (index != -1) href = href.substring(0, index);
            }
            for (int i = 0; i < count; i++) {
                addPropertyNames(document, children[i],
                        href + escape(children[i].getName()), depth);
            }
        }
    }

    private void addAllProperties(Document document, SmbFile file, String href,
            int depth) throws IOException {
        getPropertiesBuilder().addAllProps(document, file, href);
        if (depth > 0 && !file.isFile()) {
            SmbFile[] children = null;
            try {
                children = file.listFiles();
            } catch (SmbException ex) { }
            if (children == null) return;
            int count = children.length;
            if (count == 0) return;
            if (!href.endsWith("/")) href += "/";
            --depth;
            if (file.getType() == SmbFile.TYPE_WORKGROUP &&
                    !"smb://".equals(file.toString())) {
                int index = href.lastIndexOf(file.getName());
                if (index != -1) href = href.substring(0, index);
            }
            for (int i = 0; i < count; i++) {
                addAllProperties(document, children[i],
                        href + escape(children[i].getName()), depth);
            }
        }
    }

    private void addProperties(Document document, SmbFile file, String href,
            Element[] props, int depth) throws IOException {
        getPropertiesBuilder().addProps(document, file, href, props);
        if (depth > 0 && !file.isFile()) {
            SmbFile[] children = null;
            try {
                children = file.listFiles();
            } catch (SmbException ex) { }
            if (children == null) return;
            int count = children.length;
            if (count == 0) return;
            if (!href.endsWith("/")) href += "/";
            --depth;
            if (file.getType() == SmbFile.TYPE_WORKGROUP &&
                    !"smb://".equals(file.toString())) {
                int index = href.lastIndexOf(file.getName());
                if (index != -1) href = href.substring(0, index);
            }
            for (int i = 0; i < count; i++) {
                addProperties(document, children[i],
                        href + escape(children[i].getName()), props, depth);
            }
        }
    }

    private String escape(String name) throws IOException {
        boolean dir = name.endsWith("/");
        if (dir) name = name.substring(0, name.length() - 1);
        StringBuffer buffer = new StringBuffer();
        char[] chars = name.toCharArray();
        int count = chars.length;
        for (int i = 0; i < chars.length; i++) {
            if (chars[i] > 0x7f || ESCAPED[chars[i]]) {
                buffer.append("%");
                byte[] bytes = Character.toString(chars[i]).getBytes("UTF-8");
                for (int j = 0; j < bytes.length; j++) {
                    buffer.append(Integer.toHexString((bytes[j] >> 4) & 0x0f));
                    buffer.append(Integer.toHexString(bytes[j] & 0x0f));
                }
            } else {
                buffer.append(chars[i]);
            }
        }
        if (dir) buffer.append("/");
        return buffer.toString();
    }

}
