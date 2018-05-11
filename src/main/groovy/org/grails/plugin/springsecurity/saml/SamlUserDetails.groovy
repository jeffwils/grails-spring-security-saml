package org.grails.plugin.springsecurity.saml

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import grails.compiler.GrailsCompileStatic

import grails.plugin.springsecurity.userdetails.GrailsUser
import org.springframework.security.core.GrantedAuthority

@GrailsCompileStatic
@EqualsAndHashCode(includes='username')
@ToString(includes='username', includeNames=true, includePackage=false)
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

    def getProperty(String name) {
        def attribute = samlAttributes[name]
        if(attribute && !hasProperty(name)) {
            return attribute
        }
        return metaClass.getProperty(this, name)
    }
}
