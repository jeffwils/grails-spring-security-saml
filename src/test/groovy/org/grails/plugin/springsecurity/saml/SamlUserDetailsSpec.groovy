package org.grails.plugin.springsecurity.saml

import grails.test.mixin.*
import grails.testing.web.controllers.ControllerUnitTest
import spock.lang.Specification
import groovy.lang.MissingPropertyException

class SamlUserDetailsSpec extends Specification {

    String username = "jackSparrow"
    String password = "jackSparrow"
    def emailAddress = "test@mailinator.com"
    def firstname = "Jack"

    void "test access to a saml attribute"() {
        setup:
            def user = new SamlUserDetails(username, password,
                true, true, true, true, [],
                username, [emailAddress: emailAddress, firstname: firstname])

        expect:
            user.emailAddress == emailAddress
    }

    void "test access to a normal attribute"() {
        setup:
            def user = new SamlUserDetails(username, password,
                true, true, true, true, [],
                username, [emailAddress: emailAddress, firstname: firstname])

        expect:
            user.username == username
    }

    void "test access to a normal attribute with a colliding saml attribute"() {
        setup:
            def user = new SamlUserDetails(username, password,
                true, true, true, true, [],
                username, [username: firstname])

        expect: "the saml attribute will be ignored"
            user.username != firstname
            user.username == username
    }

    void "test access to an attribute that doesn't exist"() {
        setup:
            def user = new SamlUserDetails(username, password,
                true, true, true, true, [],
                username, [emailAddress: emailAddress])
        when:
            def value = user.firstname

        then:
            thrown MissingPropertyException
    }
}
