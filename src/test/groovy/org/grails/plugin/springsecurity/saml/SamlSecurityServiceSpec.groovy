package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.testing.gorm.DataTest
import grails.testing.services.ServiceUnitTest
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import spock.lang.Specification
import test.TestSamlUser

class SamlSecurityServiceSpec extends Specification implements ServiceUnitTest<SamlSecurityService>, DataTest {

    def grailsUser, authToken

    void setup() {
        mockDomain( TestSamlUser )
        grailsUser = new GrailsUser('username', 'password', true, true, true, true, [], 1)

        authToken = new UsernamePasswordAuthenticationToken(grailsUser.username, null)
        authToken.setDetails(grailsUser)

        SamlSecurityService.metaClass.static.isLoggedIn = { -> true }
        SecurityContextHolder.metaClass.static.getContext = { -> new SecurityContextImpl() }
        SecurityContextImpl.metaClass.getAuthentication = { -> authToken }

        def samlUser = new TestSamlUser(username: grailsUser.username, password: 'password')
        samlUser.save( failOnError: true )

    }

    void "getCurrentUser should return user from sesion when autocreate active flag is false"() {
        setup:
            def fakeConfig = [ saml: [ autoCreate: [ active: false ] ] ]
            service.config = fakeConfig
            service.grailsApplication = grailsApplication

        when:
            def user = service.getCurrentUser()

        then:
            user instanceof GrailsUser
            user.username == grailsUser.username
    }

    void "getCurrentUser should return user from the database when autocreate active flag is true"() {
        setup:
            def fakeConfig = [
                    userLookup: [ userDomainClassName: 'test.TestSamlUser' ],
                    saml: [ autoCreate: [
                            active: true,
                            key: 'username' ] ] ]

            service.config = fakeConfig
            service.grailsApplication = grailsApplication

        when:
            def user = service.getCurrentUser()

        then:
            user instanceof TestSamlUser
            user.username == grailsUser.username
    }

    void "getCurrentUser should return null when the user is not logged in"() {
        setup:
            SamlSecurityService.metaClass.static.isLoggedIn = { -> false }

        expect:
            !service.getCurrentUser()
    }

    void "getCurrentUser should return null when autocreate active and details from session is null"() {
        setup:
            def fakeConfig = [saml: [ autoCreate: [active: true,] ] ]

            service.config = fakeConfig
            authToken.setDetails(null)

        expect:
            !service.getCurrentUser()
    }
}
