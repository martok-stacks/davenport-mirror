Application documentation can be found in the "doc" directory ("index.html").
This file documents changes made since previous releases.

Davenport and its source code can be obtained freely from:

    http://davenport.sourceforge.net

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
