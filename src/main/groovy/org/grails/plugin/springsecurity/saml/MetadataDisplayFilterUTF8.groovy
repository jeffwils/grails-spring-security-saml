package org.grails.plugin.springsecurity.saml

import org.springframework.security.saml.metadata.MetadataDisplayFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.servlet.ServletException
import java.io.IOException
import groovy.transform.CompileStatic
import javax.servlet.ServletResponseWrapper

@CompileStatic
class MetadataDisplayFilterUTF8 extends MetadataDisplayFilter {
    @Override
    protected void processMetadataDisplay(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        // The current version of Spring Security SAML (1.02)
        // does not use UTF-8 by default
        // This workaround is no longer necessary when
        // Spring Security SAML 1.04 is released because
        // it uses UTF-8 by default
        response.setCharacterEncoding("UTF-8")
        super.processMetadataDisplay(request,response)
    }
}
