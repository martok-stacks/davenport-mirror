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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import jcifs.smb.SmbFile;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This interface provides operations for constructing and retrieving a
 * PROPFIND result XML document.
 *
 * @author Eric Glass
 */
public interface PropertiesBuilder {

    public void init(ServletConfig config) throws ServletException;

    public void destroy();

    /**
     * Adds a response containing the property names supported by the
     * given resource.
     *
     * @param document The document to which modifications are made.
     * @param file The <code>SmbFile</code> resource whose property names are
     * to be retrieved.
     * @param href The HTTP URL by which the resource was accessed.
     * @throws IOException If an IO error occurs while adding the
     * property names.
     */
    public void addPropNames(Document document, SmbFile file, String href)
            throws IOException;

    /**
     * Adds a response containing the names and values of all properties
     * supported by the given resource.
     *
     * @param file The <code>SmbFile</code> resource whose property names
     * and values are to be retrieved.
     * @param href The HTTP URL by which the resource was accessed.
     * @throws IOException If an IO error occurs while adding the
     * properties.
     */
    public void addAllProps(Document document, SmbFile file, String href)
            throws IOException;

    /**
     * Adds a response containing the names and values of the properties
     * specified by the given <code>Element</code> array.
     *
     * @param file The <code>SmbFile</code> resource whose properties
     * are to be retrieved.
     * @param href The HTTP URL by which the resource was accessed.
     * @param props An array of <code>Element</code>s, each of which
     * specifies the name of a property to be retrieved.
     * @throws IOException If an IO error occurs while adding the
     * properties.
     */
    public void addProps(Document document, SmbFile file, String href,
            Element[] props) throws IOException;

    /**
     * Creates an XML document in which a result can be built.
     *
     * @return A <code>Document</code> object to hold the resulting
     * XML.
     */
    public Document createDocument();

}
