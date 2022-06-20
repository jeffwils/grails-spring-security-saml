package org.grails.plugin.springsecurity.saml;

import org.springframework.core.convert.converter.Converter
import javax.servlet.http.HttpServletRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;

public class DefaultRegistrationResolver implements Converter<HttpServletRequest, RelyingPartyRegistration> {

    def relyingPartyRegistrationResolver
    def defaultRegistration

    RelyingPartyRegistration convert(HttpServletRequest request) {
        return relyingPartyRegistrationResolver.resolve(request, defaultRegistration)
    }
}
