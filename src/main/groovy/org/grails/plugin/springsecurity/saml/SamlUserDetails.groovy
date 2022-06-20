package org.grails.plugin.springsecurity.saml

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import grails.compiler.GrailsCompileStatic

import grails.plugin.springsecurity.userdetails.GrailsUser
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import java.io.Serializable
import org.springframework.util.Assert


@GrailsCompileStatic
class SamlUserDetails extends GrailsUser implements Saml2AuthenticatedPrincipal, Serializable  {

    private final String name

    private Map<String, List<Object>> attributes

    private String registrationId

    SamlUserDetails(String username, String password, boolean enabled,
                boolean accountNonExpired, boolean credentialsNonExpired,
                boolean accountNonLocked,
                Collection<GrantedAuthority> authorities,
                id, Map<String, List<Object>> attributes) {
        super(username, password, enabled, accountNonExpired,
               credentialsNonExpired, accountNonLocked, authorities, id)

        Assert.notNull(username, "username cannot be null");
        Assert.notNull(attributes, "attributes cannot be null");
        this.name = username;
        this.attributes = attributes;
        this.registrationId = null;
    }

    public void setAttributes(Map<String, List<Object>> attributes) {
        this.attributes = attributes
    }

    def getProperty(String name) {
        List<Object> attribute = attributes[name]
        if(attributes.containsKey(name) && !hasProperty(name) && !attribute.isEmpty()) {
            return attribute[0]
        }
        return metaClass.getProperty(this, name)
    }

    @Override
    public String getName() {
        return this.name;
    }

    @Override
    public Map<String, List<Object>> getAttributes() {
        return this.attributes;
    }

    @Override
    public String getRelyingPartyRegistrationId() {
        return this.registrationId;
    }

    public void setRelyingPartyRegistrationId(String registrationId) {
        Assert.notNull(registrationId, "relyingPartyRegistrationId cannot be null");
        this.registrationId = registrationId;
    }
}
