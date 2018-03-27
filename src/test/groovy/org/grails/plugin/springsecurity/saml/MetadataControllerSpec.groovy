package org.grails.plugin.springsecurity.saml

import grails.test.mixin.*
import grails.testing.web.controllers.ControllerUnitTest
import org.junit.*
import spock.lang.Specification

class MetadataControllerSpec extends Specification implements ControllerUnitTest<MetadataController> {

    def metadata

    @Before
    void init() {
        metadata = [hostedSPName: 'splocal', SPEntityNames: ['testsp'], IDPEntityNames: ['testidp'] ]
        controller.metadata = metadata
    }

    void testIndexReturnsMetadataValuesInModel() {
        def model = controller.index()

        assert model.hostedSP == metadata.hostedSPName
        assert model.spList == metadata.SPEntityNames
        assert model.idpList == metadata.IDPEntityNames
    }
}
