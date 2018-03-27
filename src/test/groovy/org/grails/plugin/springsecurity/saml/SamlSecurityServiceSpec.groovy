package org.grails.plugin.springsecurity.saml

import grails.test.mixin.*
import grails.plugin.springsecurity.userdetails.GrailsUser
import grails.testing.gorm.DataTest
import grails.testing.services.ServiceUnitTest
import org.junit.Before
import org.junit.Test
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.context.SecurityContextImpl
import spock.lang.Specification
import test.TestSamlUser

class SamlSecurityServiceSpec extends Specification implements ServiceUnitTest<SamlSecurityService>, DataTest {

    def grailsUser, authToken

    @Before
    void init() {
        mockDomain( TestSamlUser )
        grailsUser = new GrailsUser('username', 'password', true, true, true, true, [], 1)

        authToken = new UsernamePasswordAuthenticationToken(grailsUser.username, null)
        authToken.setDetails(grailsUser)

        SamlSecurityService.metaClass.static.isLoggedIn = { -> true }
        SecurityContextHolder.metaClass.static.getContext = { -> new SecurityContextImpl() }
        SecurityContextImpl.metaClass.getAuthentication = { -> authToken }

        def samlUser = new TestSamlUser(username: grailsUser.username, password: 'password')
        assert samlUser.save()

    }

    @Test
    void "getCurrentUser should return user from sesion when autocreate active flag is false"() {
        def fakeConfig = [ saml: [ autoCreate: [ active: false ] ] ]

        service.config = fakeConfig
        service.grailsApplication = grailsApplication

        def user = service.getCurrentUser()
        assert user instanceof GrailsUser
        assert user.username == grailsUser.username
    }

    @Test
    void "getCurrentUser should return user from the database when autocreate active flag is true"() {
        def fakeConfig = [
                userLookup: [ userDomainClassName: USER_CLASS_NAME ],
                saml: [ autoCreate: [
                        active: true,
                        key: 'username' ] ] ]

        service.config = fakeConfig
        service.grailsApplication = grailsApplication

        def user = service.getCurrentUser()
        assert user instanceof TestSamlUser
        assert user.username == grailsUser.username
    }

    @Test
    void "getCurrentUser should return null when the user is not logged in"() {
        SamlSecurityService.metaClass.static.isLoggedIn = { -> false }
        assert !service.getCurrentUser()
    }

    @Test
    void "getCurrentUser should return null when autocreate active and details from session is null"() {
        def fakeConfig = [saml: [ autoCreate: [active: true,] ] ]

        service.config = fakeConfig
        authToken.setDetails(null)

        assert !service.getCurrentUser()
    }
}
