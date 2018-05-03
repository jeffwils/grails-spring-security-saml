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
        response.setCharacterEncoding("UTF-8")
        super.processMetadataDisplay(request,response)
    }
}
