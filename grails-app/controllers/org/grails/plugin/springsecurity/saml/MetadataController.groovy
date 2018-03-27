package org.grails.plugin.springsecurity.saml

import org.opensaml.Configuration
import org.opensaml.saml2.metadata.provider.MetadataProvider
import org.opensaml.xml.io.Marshaller
import org.opensaml.xml.io.MarshallerFactory
import org.opensaml.xml.io.MarshallingException
import org.opensaml.xml.security.credential.Credential
import org.opensaml.xml.util.XMLHelper
import org.springframework.security.saml.metadata.ExtendedMetadata
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate
import org.springframework.security.saml.metadata.MetadataMemoryProvider
import org.w3c.dom.Element

import java.security.KeyStoreException
import org.opensaml.common.xml.SAMLConstants

/**
 * @author alvaro.sanchez
 */
class MetadataController {

    def metadataGenerator
    def metadata
    def keyManager

    def index = {
        log.trace 'in index'
        metadata.SPEntityNames.each{
            log.trace "${it}"
        }
        [hostedSP: metadata.hostedSPName, spList: metadata.SPEntityNames, idpList: metadata.IDPEntityNames]
    }

    def show = {
        log.trace "in show: ${params.entityId}"
        def entityDescriptor = metadata.getEntityDescriptor(params.entityId)
        if(!entityDescriptor) {
            notFound()
            return
        }
        def extendedMetadata = metadata.getExtendedMetadata(params.entityId)
        def storagePath = getFileName(entityDescriptor)
        def serializedMetadata = getMetadataAsString(entityDescriptor)

        [entityDescriptor: entityDescriptor, extendedMetadata: extendedMetadata,
         storagePath: storagePath, serializedMetadata: serializedMetadata]
    }

    def create = {
        def availableKeys = getAvailablePrivateKeys()
        def baseUrl = "${request.scheme}://${request.serverName}:${request.serverPort}${request.contextPath}"

        log.trace "In Create Server name ${request.serverName} used as entity id and alias - baseUrl ${baseUrl}"
        def entityId = request.serverName
        def alias = entityId



        [availableKeys: availableKeys, baseUrl: baseUrl, entityId: entityId, alias: alias]
    }

    def save = {

        log.trace "in save: ${params.entityId}"

        metadataGenerator.setEntityId(params.entityId)
        metadataGenerator.setEntityBaseURL(params.baseURL)
        metadataGenerator.setRequestSigned(params.requestSigned as boolean)
        metadataGenerator.setWantAssertionSigned(params.wantAssertionSigned as boolean)

        def bindingsSSO = []

        if (params.ssoBindingPost as boolean)
        {
            bindingsSSO << SAMLConstants.SAML2_POST_BINDING_URI
        }

        if (params.ssoBindingPAOS as boolean)
        {
            bindingsSSO << SAMLConstants.SAML2_PAOS_BINDING_URI
        }

        if (params.ssoBindingArtifact as boolean)
        {
            bindingsSSO <<  SAMLConstants.SAML2_ARTIFACT_BINDING_URI
        }

        metadataGenerator.setBindingsSSO((Collection<String>) bindingsSSO)

        metadataGenerator.setIncludeDiscoveryExtension(params.includeDiscovery as boolean)

        def descriptor = metadataGenerator.generateMetadata()

        ExtendedMetadata extendedMetadata = metadataGenerator.generateExtendedMetadata()
        extendedMetadata.setAlias(params.alias)
        extendedMetadata.setSignMetadata(params.signMetadata as boolean)
        extendedMetadata.setSigningKey(params.signingKey)
        extendedMetadata.setEncryptionKey(params.encryptionKey)
        extendedMetadata.setTlsKey(params.tlsKey)
        extendedMetadata.setSecurityProfile(params.securityProfile)
        extendedMetadata.setRequireLogoutRequestSigned(params.requireLogoutRequestSigned as boolean)
        extendedMetadata.setRequireLogoutResponseSigned(params.requireLogoutResponseSigned as boolean)
        extendedMetadata.setRequireArtifactResolveSigned(params.requireArtifactResolveSigned as boolean)

        if (params.store) {
            MetadataMemoryProvider memoryProvider = new MetadataMemoryProvider(descriptor)
            memoryProvider.initialize()
            MetadataProvider metadataProvider = new ExtendedMetadataDelegate(memoryProvider, extendedMetadata)
            metadata.addMetadataProvider(metadataProvider)
            metadata.setHostedSPName(descriptor.entityID)
            metadata.setRefreshRequired(true)
            metadata.refreshMetadata()
        }

        redirect(action: 'show', params: [entityId: params.entityId])
    }

    protected def getFileName(entityDescriptor) {
        StringBuilder fileName = new StringBuilder()
        for (Character c : entityDescriptor.getEntityID().toCharArray()) {
            if (Character.isJavaIdentifierPart(c)) {
                fileName.append(c)
            }
        }
        if (fileName.length() > 0) {
            fileName.append("_sp.xml")
            fileName.toString()
        } else {
            "default_sp.xml"
        }
    }

    protected def getMetadataAsString(entityDescriptor) throws MarshallingException {
        MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory()
        Marshaller marshaller = marshallerFactory.getMarshaller(entityDescriptor)
        Element element = marshaller.marshall(entityDescriptor)
        return XMLHelper.nodeToString(element)
    }

    protected def getAvailablePrivateKeys() throws KeyStoreException {
        Map<String, String> availableKeys = new HashMap<String, String>()
        Set<String> aliases = keyManager.getAvailableCredentials()
        for (String key : aliases) {
            try {
                Credential credential = keyManager.getCredential(key)
                if (credential.getPrivateKey() != null) {
                    availableKeys.put(key, key + " (" + credential.getEntityId() + ")")
                }
            } catch (Exception e) {
                log.debug("Error loading key: ${e}")
            }
        }
        availableKeys
    }

    protected void notFound() {
        flash.message = message(code: 'default.not.found.message', args: ["entityId", params.entityId])
        redirect action: "index", method: "GET"
    }
}
