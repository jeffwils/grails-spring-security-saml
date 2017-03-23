package org.grails.plugin.springsecurity.saml

import grails.plugin.springsecurity.SpringSecurityUtils
import org.opensaml.xml.Configuration
import org.opensaml.xml.util.XMLConstants
import org.opensaml.xml.security.BasicSecurityConfiguration
import org.opensaml.xml.signature.SignatureConstants
import org.springframework.beans.BeansException
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory
import org.springframework.security.saml.SAMLBootstrap

public final class CustomSAMLBootstrap extends SAMLBootstrap {


    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

        def conf = SpringSecurityUtils.securityConfig
        super.postProcessBeanFactory(beanFactory);
        def sigAlgorithmConfig = (conf.saml.signatureAlgorithm) ? SignatureConstants.MORE_ALGO_NS + conf.saml.signatureAlgorithm : SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1
        def digestAlgorithmConfig = (conf.saml.digestAlgorithm) ? XMLConstants.XMLENC_NS  + conf.saml.digestAlgorithm : SignatureConstants.ALGO_ID_DIGEST_SHA1
        BasicSecurityConfiguration config = (BasicSecurityConfiguration) Configuration.getGlobalSecurityConfiguration();
        config.registerSignatureAlgorithmURI("RSA", sigAlgorithmConfig);
        config.setSignatureReferenceDigestMethod(digestAlgorithmConfig);

    }

    private String getConfigMapping(String configSignature){

    }
}
