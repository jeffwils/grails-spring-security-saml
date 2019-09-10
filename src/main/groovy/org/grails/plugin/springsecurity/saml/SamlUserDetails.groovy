package org.grails.plugin.springsecurity.saml

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import grails.compiler.GrailsCompileStatic

import grails.plugin.springsecurity.userdetails.GrailsUser
import org.springframework.security.core.GrantedAuthority

@GrailsCompileStatic
class SamlUserDetails extends GrailsUser {

    private Map samlAttributes

    SamlUserDetails(String username, String password, boolean enabled,
                boolean accountNonExpired, boolean credentialsNonExpired,
                boolean accountNonLocked,
                Collection<GrantedAuthority> authorities,
                id, Map samlAttributes) {
        super(username, password, enabled, accountNonExpired,
               credentialsNonExpired, accountNonLocked, authorities, id)
        this.samlAttributes = samlAttributes
    }

    public void setSamlAttributes(Map samlAttributes) {
        this.samlAttributes = samlAttributes
    }

    def getProperty(String name) {
        def attribute = samlAttributes[name]
        if(samlAttributes.containsKey(name) && !hasProperty(name)) {
            return attribute
        }
        return metaClass.getProperty(this, name)
    }
}
