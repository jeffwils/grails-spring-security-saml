package org.grails.plugin.springsecurity.saml

import grails.testing.mixin.integration.Integration
import grails.transaction.Rollback
import spock.lang.Specification
import test.TestUserRole
import test.TestSamlUser
import test.TestRole
import org.springframework.security.saml.SAMLCredential
import org.opensaml.saml2.core.impl.NameIDImpl
import org.opensaml.saml2.core.impl.AssertionImpl
import grails.core.GrailsApplication

@Integration
@Rollback
class SpringSamlUserDetailsServiceIntegrationSpec extends Specification {

    String username = "jackSparrow"

    GrailsApplication grailsApplication

    def "Test getting user details from db"() {
        given:
            TestSamlUser user = new TestSamlUser(
                    username:username,
                    email:'bob@fake.com',
                    password: 'test'
            ).save( failOnError: true )
            TestRole role = new TestRole(authority:"testauth").save( failOnError: true )
            TestUserRole.create( user,  role )

            SpringSamlUserDetailsService service = new SpringSamlUserDetailsService(
                    samlAutoAssignAuthorities: false,
                    samlAutoCreateActive: true,
                    userDomainClassName: "test.TestSamlUser",
                    samlAutoCreateKey: 'username',
                    authorityNameField: 'authority',
                    authorityJoinClassName: 'test.TestUserRole')
            service.grailsApplication = grailsApplication

        when:
            SAMLCredential cred
            cred = new SAMLCredential(
                    new NameIDImpl("", "", ""),
                    new AssertionImpl("", "", ""),
                    null,
                    null)
            cred.metaClass.getNameID = { [value: "$username"] }
            def loadedUser = service.loadUserBySAML(cred)

        then:
            user.username == username
            user.email == 'bob@fake.com'
            loadedUser
            loadedUser.username == username
    }

}
