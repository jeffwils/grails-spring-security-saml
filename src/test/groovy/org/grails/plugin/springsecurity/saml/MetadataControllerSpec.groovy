package org.grails.plugin.springsecurity.saml

import grails.test.mixin.*
import grails.testing.web.controllers.ControllerUnitTest
import spock.lang.Specification

class MetadataControllerSpec extends Specification implements ControllerUnitTest<MetadataController> {

    def testMetadata

    void setup() {
        testMetadata = [hostedSPName: 'splocal', SPEntityNames: ['testsp'], IDPEntityNames: ['testidp'] ]
        controller.metadata = testMetadata
    }

    void testIndexReturnsMetadataValuesInModel() {
        setup:
            def model = controller.index()

        expect:
            model.hostedSP == testMetadata.hostedSPName
            model.spList == testMetadata.SPEntityNames
            model.idpList == testMetadata.IDPEntityNames
    }
}
