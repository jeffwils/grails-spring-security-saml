package org.grails.plugin.springsecurity.saml

import grails.testing.mixin.integration.Integration
import grails.transaction.Rollback
import org.springframework.security.core.userdetails.UserDetails
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

    GrailsApplication grailsApplication

    private final String testUsername = 'jackSparrow'
    private final String testEmail = 'bob@fake.com'
    private final String testPassword = 'test'
    private final String userDomainClassName = "test.TestSamlUser"
    private final String authorityNameField = 'authority'
    private String authorityJoinClassName = 'test.TestUserRole'

    def "Test getting user details from db"() {
        given:
            TestSamlUser user = new TestSamlUser(
                    username: testUsername,
                    email:    testEmail,
                    password: testPassword
            ).save( failOnError: true )
            TestRole role = new TestRole(authority:"testauth").save( failOnError: true )
            TestUserRole.create( user,  role )

            SpringSamlUserDetailsService service = new SpringSamlUserDetailsService(
                    samlAutoAssignAuthorities: false,
                    samlAutoCreateActive: true,
                    userDomainClassName: userDomainClassName,
                    samlAutoCreateKey: 'username',
                    authorityNameField: authorityNameField,
                    authorityJoinClassName: authorityJoinClassName)
            service.grailsApplication = grailsApplication

        when:
            UserDetails loadedUser = (UserDetails)service.loadUserBySAML( buildSamlCredential( testUsername ) )

        then:
            user.username == testUsername
            user.email == testEmail
            loadedUser
            loadedUser.username == testUsername
    }

    def 'Test retrieval of user roles from local DB'() {
        given: 'A user with some roles and configuration to use local roles'
            TestSamlUser user = new TestSamlUser(
                    username: testUsername,
                    email: testEmail,
                    password: testPassword
            ).save( failOnError: true )
            ['role1', 'role2', 'role3', 'role4'].each { roleName ->
                def role = new TestRole( authority: roleName ).save( failOnError: true )
                TestUserRole.create( user, role )
            }
            SpringSamlUserDetailsService service = new SpringSamlUserDetailsService(
                    samlUseLocalRoles:         true, // the key configuration param
                    samlAutoAssignAuthorities: false,
                    samlAutoCreateActive:      false,
                    userDomainClassName:       userDomainClassName,
                    authorityNameField:        authorityNameField,
                    authorityJoinClassName:    authorityJoinClassName )
            service.grailsApplication = grailsApplication

        when: 'We attempt to retrieve the user based on SAML Credentials'
            UserDetails loadedUser = (UserDetails)service.loadUserBySAML( buildSamlCredential( testUsername ) )
            def loadedRoles = TestSamlUser.findByUsername( testUsername ).authorities

        then: 'the user is returned with roles which match their DB roles'
            loadedUser.username == testUsername
            loadedUser.authorities.size() == loadedRoles.size()
            loadedUser.authorities*.authority.containsAll( loadedRoles*.authority )
    }

    private static SAMLCredential buildSamlCredential(String username ) {
        SAMLCredential cred
        cred = new SAMLCredential(
                new NameIDImpl("", "", ""),
                new AssertionImpl("", "", ""),
                null,
                null)
        cred.metaClass.getNameID = { [value: "$username"] }

        cred
    }
}
