Application documentation can be found in the "doc" directory ("index.html").
This file documents changes made since previous releases.

Davenport and its source code can be obtained freely from:

    http://davenport.sourceforge.net

--------------------------------------------------------------------------------
Version 0.9.7: February 10, 2004

SUMMARY OF CHANGES:
    Fixed a bug involving redirects for directories not ending in "/".
    Fixed various bugs involving incorrect WebDAV properties.
    Added additional localization support.


CHANGE:
    Fixed a bug involving redirects for directories not ending in "/".
DETAILS:
    Davenport should redirect requests for collections not ending in "/" to
    the "/"-terminated location.  This was previously only being done for
    GET requests.
RESOLUTION:
    Davenport now redirects requests via GET, HEAD, OPTIONS, and PROPFIND.


CHANGE:
    Fixed various bugs involving incorrect WebDAV properties.
DETAILS:
    There were various cases in which Davenport presented WebDAV properties
    containing invalid values.  These have been removed.
RESOLUTION:
    Excluded the "creationdate" and "getlastmodified" properties for
    resources on which these values do not exist.
    Excluded the "getcontentlength" property for collections.
    Excluded collections from ETag generation.


CHANGE:
    Added additional localization support.
DETAILS:
    Directory stylesheets and the configuration page can now use a
    mechanism similar to resource bundles to support localization.

--------------------------------------------------------------------------------
Version 0.9.6: February 9, 2004

SUMMARY OF CHANGES:
    Fixed a bug involving date formatting in some WebDAV properties.
    Added a configuration option to accept HTTP Basic credentials if
    proactively offered by the client.
    Added a configuration option to disable NTLM authentication for improved
    functionality in Windows 2003 environments.
    Added a build target to reconfigure the WAR file using an updated
    deployment descriptor.
    Added preliminary localization support.
    Updated bundled jCIFS to version 0.7.19.


CHANGE:
    Fixed a bug involving date formatting in some WebDAV properties.
DETAILS:
    The date formatter used to produce the value for the "getcreationdate"
    and "getlastmodified" properties used the platform's default locale.
    This would result in invalid HTTP date formats on non-English platforms.
RESOLUTION:
    Specified the US locale for the relevant date formatters.


CHANGE:
    Added a configuration option to accept HTTP Basic credentials if
    proactively offered by the client.
DETAILS:
    Added the "acceptBasic" configuration option.  This will use HTTP
    Basic authentication if it is presented by the client, even if
    Davenport is not configured to offer HTTP Basic.  This is useful
    for clients that revert to HTTP Basic when presented with unrecognized
    authentication mechanisms (such as NTLM).  Additionally, some containers
    have been found to support only a single mechanism at a time, preventing
    Davenport from offering both NTLM and Basic.  This setting would allow
    such installations to offer only NTLM, but accept Basic from clients
    that don't support NTLM.


CHANGE:
    Added a configuration option to disable NTLM authentication for improved
    functionality in Windows 2003 environments.
DETAILS:
    Added the "enableNtlm" configuration option.  When set to "false", this
    will prevent Davenport from offering NTLM authentication.  By default,
    Windows 2003 servers are configured to require SMB signing.  jCIFS will
    support SMB signing, but the password is required.  Davenport only has
    access to the user's password under HTTP Basic authentication.  This
    setting can allow Davenport to operate in such an environment.  Note
    that Basic authentication is highly insecure; appropriate precautions
    should be taken by administrators if this approach is taken.


CHANGE:
    Added a build target to reconfigure the WAR file using an updated
    deployment descriptor.
DETAILS:
    The Ant build script now includes a "reconfig" target which will refresh
    "davenport.war" with the current deployment descriptor ("web.xml") from
    the source tree.  This simplifies the process of tuning the deployment
    descriptor to the local environment.


CHANGE:
    Added preliminary localization support.
DETAILS:
    Error messages and other strings previously hardcoded in the application
    source are now loaded from a resource bundle.  This facilitates translation
    to other languages and localities.


CHANGE:
    Updated bundled jCIFS to version 0.7.19.
DETAILS:
    jCIFS 0.7.19 includes numerous enhancements over the previous bundled
    version (0.7.11).  This includes support for SMB signing, which is
    required by default for interoperability with Windows 2003 servers.

--------------------------------------------------------------------------------
Version 0.9.5: July 16, 2003

Very special thanks to Ronald Tschalär, who identified and provided patches for
nearly all of the items in this release (including all bugfixes).  As a result,
WebDAV functionality with several clients has been significantly improved.

Note that the default authentication behavior has changed when accessing
resources; Davenport will now require authentication only when demanded by
the underlying resource.  This implies that publicly accessible shares may now
be publicly accessible through Davenport as well.  The previous behavior can
be enabled by setting the "alwaysAuthenticate" parameter to "true"; this will
request authentication when accessing any resource on a given server.

SUMMARY OF CHANGES:
    Fixed a bug involving the status code in the PROPFIND response.
    Fixed a bug involving the status code in the MKCOL response.
    Fixed a bug involving missing namespace declarations in the PROPFIND
    document.
    Changed the getcontenttype value for collections.
    Changed the default authentication behavior for anonymous browsing.
    Set the content length in the response for all handlers.
    Added support for LMv2 authentication.
    Added technical documentation on the NTLM authentication protocol.
    Updated bundled jCIFS to version 0.7.11, and changed the minimum
    jCIFS version to 0.7.11.


CHANGE:
    Fixed a bug involving the status code in the PROPFIND response.
DETAILS:
    The PROPFIND response previously returned a status code of 200 ("OK")
    rather than 207 ("Multi-Status").  This was a bug in Davenport.
RESOLUTION:
    Fixed to return status code 207 ("Multi-Status").


CHANGE:
    Fixed a bug involving the status code in the MKCOL response.
DETAILS:
    The PROPFIND response previously returned a status code of 200 ("OK")
    rather than 201 ("Created").  This was a bug in Davenport.
RESOLUTION:
    Fixed to return status code 201 ("Created").


CHANGE:
    Fixed a bug involving missing namespace declarations in the PROPFIND
    document.
DETAILS:
    The PROPFIND XML document previously only added declarations for
    the standard "DAV:" namespace and the Microsoft attribute namespace.
    PROPFIND requests which included elements from other namespaces would
    result in missing namespace declarations in the resulting document.
    This was a bug in Davenport.
RESOLUTION:
    Fixed to add new namespace declarations as encountered.


CHANGE:
    Changed the getcontenttype value for collections.
DETAILS:
    Under Konqueror, the folder icon is not displayed for collection resources
    unless the value of the getcontenttype property is "httpd/unix-directory".
    Previous versions of Davenport used "application/octet-stream" as the value
    for this property.  While the value is undefined in the WebDAV
    specification, it does indicate that it should match the value of the
    Content-Type header in the GET response (which would be neither
    "application/octet-stream" or "httpd/unix-directory", but "text/html").
    After weighing the advantages and disadvantages, the decision was made
    to break from the specification and use "httpd/unix-directory" to better
    support Konqueror users.  This may change in future Davenport revisions
    if it is determined to cause issues with WebDAV clients which enforce
    the specification semantics.


CHANGE:
    Changed the default authentication behavior for anonymous browsing.
DETAILS:
    Previous versions of Davenport always authenticated the user, even when
    anonymous access was allowed to a given resource.  The default behavior
    has been changed to only request authentication when it is required by
    the resource being accessed.  A servlet parameter, "alwaysAuthenticate",
    has been added to revert to the previous behavior.


CHANGE:
    Set the content length in the response for all handlers.
DETAILS:
    Some of the request handlers did not set an explicit content length.
    While not technically an error, it was inconsistent behavior.


CHANGE:
    Added support for LMv2 authentication.
DETAILS:
    With jCIFS 0.7.11, support for LMv2 authentication has been added.  This
    provides a more secure authentication scheme than standard NTLM.
    Documentation on the "jcifs.smb.lmCompatibility" property has been added,
    providing instructions on enabling LMv2 authentication.


CHANGE:
    Added technical documentation on the NTLM authentication protocol.
DETAILS:
    Compiled a body of documentation on the NTLM authentication protocol, used
    as the basis for LMv2 support in jCIFS and as a general developer's
    reference on NTLM.


CHANGE:
    Updated bundled jCIFS to version 0.7.11, and changed the minimum
    jCIFS version to 0.7.11.
DETAILS:
    jCIFS 0.7.11 includes numerous fixes identified since the release of the
    previous bundled version (0.7.6), and includes support for LMv2
    authentication.  A minor change to the Davenport authentication code
    relies on a 0.7.11 API enhancement.

--------------------------------------------------------------------------------
Version 0.9.0: May 12, 2003

SUMMARY OF CHANGES:
    Fixed a bug involving the encoding of non-ASCII URL characters.
    Fixed issue with Windows' Web Folders involving "drilling down" from
    workgroups.
    Fixed issue with Windows' Web Folders and non-ASCII URL characters.
    Davenport can now be properly built on JDK 1.3.1 or higher (rather than
    requiring 1.4).
    Ant build file changed to allow building with older versions of Ant.
    Updated bundled jCIFS to version 0.7.6.


CHANGE:
    Fixed a bug involving the encoding of non-ASCII URL characters.
DETAILS:
    Multibyte UTF-8 characters were being encoded as "%aabb",
    rather than "%aa%bb".  This was a bug in Davenport.
RESOLUTION:
    Fixed to encode as "%aa%bb".


CHANGE:
    Fixed issue with Windows' Web Folders involving "drilling down" from
    workgroups.
DETAILS:
    SMB URLs are not strictly hierarchical, in that smb://foo could represent
    either workgroup "foo" or server "foo".  When drilling down from workgroup
    "foo" to server "foobar", the correct transition is "smb://foo/" ->
    "smb://foobar".  Microsoft's Web Folders implementation constructs child
    resources using the current resource URL as a base URI (rather than
    respecting the URL specified in the propfind result).  This effectively
    caused Davenport to access the server as "smb://foo/foobar/".
RESOLUTION:
    As workgroups are encountered, they are now cached; attempts to access
    hierarchically represented server URLs (such as "smb://foo/foobar/") are
    now converted to the correct form ("smb://foobar/") before use by the
    application.  It is possible to subvert this mechanism by directly
    accessing a server "foobar" as "smb://foo/foobar/" before first accessing
    the workgroup; however, this would not occur when drilling down, and is
    technically an incorrect SMB URL in any case.


CHANGE:
    Fixed issue with Windows' Web Folders and non-ASCII URL characters.
DETAILS:
    Web Folders uses the local character set when encoding non-ASCII URL
    characters, rather than UTF-8 (this applies even when "Always send URLs as
    UTF-8" has been selected from the Internet Explorer options).  As a
    result, non-ASCII characters are unrecognized by Davenport.
RESOLUTION:
    An initialization parameter ("request-uri.charset") has been added to
    specify the character set that should be used to interpret the request
    URI.  This has been defaulted to "ISO-8859-1".  UTF-8 is used as a fallback
    in the event that the resource cannot be located, and should always work.
    Note that this will cause issues if the local character set used by the
    client does not match the server character set specified here.  Also, this
    will still not work under servlet containers which only accept UTF-8
    encoded request URIs (such as Caucho's Resin).  Note that this is NOT a
    bug in Resin; no interpretation is mandated for non-ASCII characters in
    URLs, and UTF-8 is the recommended best practice for handling such
    characters.  However, this will prevent interoperability between
    Web Folders and Davenport running under Resin when accessing files
    containing non-ASCII characters.


CHANGE:
    Davenport can now be properly built on JDK 1.3.1 or higher (rather than
    requiring 1.4).
DETAILS:
    The smbdav.PropertiesDirector class previously contained a call to the
    Character.toString(char) method from 1.4.
RESOLUTION:
    This was the only item preventing Davenport from working on 1.3.1;
    this was changed to extend compliance.


CHANGE:
    Ant build file changed to allow building with older versions of Ant.
DETAILS:
    The build.xml contained task definitions specific to Ant 1.5 which
    prevented the build from working under older versions of Ant.
RESOLUTION:
    The build file was rewritten to accommodate older versions of Ant.  It
    should work on versions going back to at least Ant 1.3.  The only
    1.5-specific task which remains is "checksum" (used to calculate the MD5
    sums of the distribution files).  This task is not necessary to compile
    or deploy Davenport successfully.


CHANGE:
    Updated bundled jCIFS to version 0.7.6.

--------------------------------------------------------------------------------
Version 0.8.0: April 8, 2003

This is the initial public release of the Davenport application.
