package org.grails.plugin.springsecurity.saml;

import org.springframework.core.convert.converter.Converter
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider;
import org.springframework.security.saml2.provider.service.authentication.OpenSamlAuthenticationProvider.ResponseToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken

public class SamlResponseAuthenticationConverter implements Converter<ResponseToken, AbstractAuthenticationToken> {

    SpringSamlUserDetailsService userDetailsService

    AbstractAuthenticationToken convert(ResponseToken responseToken) {
        Saml2Authentication authentication = OpenSamlAuthenticationProvider
                .createDefaultResponseAuthenticationConverter()
                .convert(responseToken);
        Saml2AuthenticatedPrincipal principal = (Saml2AuthenticatedPrincipal)authentication.principal;
        UserDetails userDetails = userDetailsService.loadUserBySAML(principal);
        userDetails.relyingPartyRegistrationId = principal.relyingPartyRegistrationId
        def customAuthentication = new Saml2Authentication(userDetails, authentication.saml2Response, getEntitlements(userDetails));
        customAuthentication.setDetails(userDetails)
        return customAuthentication
    }

    public Collection<? extends GrantedAuthority> getEntitlements(Object userDetail)
    {
        //logger.info("****** object is instance of UserDetails :"+ (userDetail instanceof UserDetails));

        if (userDetail instanceof UserDetails)
        {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.addAll(((UserDetails) userDetail).getAuthorities());
            return authorities;
        }
        else if(userDetail instanceof UsernamePasswordAuthenticationToken)
        {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.addAll(((UsernamePasswordAuthenticationToken) userDetail).getAuthorities());
            return authorities;

        } else {
            return Collections.emptyList();
        }
    }
}
