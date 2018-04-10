package org.grails.plugin.springsecurity.saml

import grails.testing.web.taglib.TagLibUnitTest
import grails.util.Holders
import spock.lang.Ignore
import spock.lang.Specification

class SamlTagLibSpec extends Specification implements TagLibUnitTest<SamlTagLib> {
    // Uses the default as specified in conf/plugin.yml
    private static final IDP_PARAM = 'idp=security/idp-local.xml'

    // Curious this, as although the ignore says there's a bug, the 'loginLinkShouldSetBody' test looks to be doing
    // same test but with different expected outcome. Can this just be removed? (Leaving ignore for now.)
    @Ignore("currently has a bug and requires rework (no yak shave)")
    void loginLinkRendersCorrectUrl() {
        expect:
            applyTemplate('<sec:loginLink>Login</sec:loginLink>') == '<a href=\'/saml/login\'>Login</a>'
    }

    void loginLinkShouldSetBody() {
        given:
            def body = "Login here"

        expect:
            applyTemplate("<sec:loginLink>${body}</sec:loginLink>") ==
                    "<a href=\'[:]?${IDP_PARAM}\'>${body}</a>"
    }

    void loginLinkShouldSetClassAttribute() {
        expect:
            def expectedClass = 'loginBtn link'
            def expectedLink = "<a href=\'[:]?${IDP_PARAM}\' class=\'$expectedClass\'>Login</a>"
            applyTemplate("<sec:loginLink class=\'${expectedClass}\'>Login</sec:loginLink>") == expectedLink
    }

    void loginLinkShouldSetIdAttribute() {
        expect:
            def expectedId = 'loginBtn'
            def expectedLink = "<a href=\'[:]?${IDP_PARAM}\' id=\'$expectedId\'>Login</a>"
            applyTemplate("<sec:loginLink id=\'${expectedId}\'>Login</sec:loginLink>") == expectedLink
    }

    void logoutLinkShouldRenderCorrectUrl() {
        given:
            mockConfig()
            def expectedLink = '<a href=\'/saml/logout\'>Logout</a>'

        expect:
            applyTemplate('<sec:logoutLink>Logout</sec:logoutLink>') == expectedLink
    }

    void logoutLinkShouldDefaultToCoreLogoutUrl() {
        given:
            mockConfig(false)
            def expectedLink = "<a href=\'${SamlTagLib.LOGOUT_SLUG}\'>Logout</a>"

        expect:
            applyTemplate('<sec:logoutLink>Logout</sec:logoutLink>') == expectedLink
    }

    void logouLinkShouldDefaultToCoreLogoutUrlWithLocal() {
        given:
            mockConfig(false)
            def expectedLink = "<a href=\'${SamlTagLib.LOGOUT_SLUG}?local=true\'>Logout</a>"

        expect:
            applyTemplate('<sec:logoutLink local="true">Logout</sec:logoutLink>') == expectedLink
    }


    void logoutLinkShouldSetBody() {
        given:
            mockConfig()
            def body = "Logout here"
            def expectedLink = "<a href=\'/saml/logout\'>${body}</a>"

        expect:
            applyTemplate("<sec:logoutLink>${body}</sec:logoutLink>") == expectedLink
    }

    void logoutLinkShouldSetClassAttribute() {
        given:
            mockConfig()
            def expectedClass = 'logoutBtn link'
            def expectedLink = "<a href=\'/saml/logout\' class=\'$expectedClass\'>Logout</a>"

        expect:
            applyTemplate("<sec:logoutLink class=\'${expectedClass}\'>Logout</sec:logoutLink>") == expectedLink
    }

    void logoutLinkShouldSetIdAttribute() {
        given:
            mockConfig()
            def expectedId = 'logoutBtn'
            def expectedLink = "<a href=\'/saml/logout\' id=\'$expectedId\'>Logout</a>"

        expect:
            applyTemplate("<sec:logoutLink id=\'${expectedId}\'>Logout</sec:logoutLink>") == expectedLink
    }

    private void mockConfig(boolean samlActive=true) {
        Holders.grailsApplication.config.grails.plugin.springsecurity.saml.active = samlActive
        Holders.grailsApplication.config.grails.plugin.springsecurity.auth.loginFormUrl = [:]
    }
}
