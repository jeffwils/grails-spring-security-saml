package org.grails.plugin.springsecurity.saml;

/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import groovy.util.logging.Log;
import groovy.util.logging.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.saml.SAMLAuthenticationProvider;
import org.springframework.security.saml.SAMLCredential;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.logging.Logger;

/**
 * A {@link org.springframework.security.saml.SAMLAuthenticationProvider} subclass to return
 * principal as UserDetails Object.
 *
 * @author feroz.panwaskar
 */

public class GrailsSAMLAuthenticationProvider extends SAMLAuthenticationProvider {
    public GrailsSAMLAuthenticationProvider() {
        super();
    }

    Logger logger;

    /**
     * @param credential credential used to authenticate user
     * @param userDetail loaded user details, can be null
     * @return principal to store inside Authentication object
     */
    @Override
    protected Object getPrincipal(SAMLCredential credential, Object userDetail) {
        //logger.info("JEFFWILS - getPrincipal " + userDetail.toString());
        if (userDetail != null) {
           // logger.info("Principal Exists");
            return userDetail;
        }
        //logger.info("Return Name ID");
        return credential.getNameID().getValue();
    }

    @Override
    public Collection<? extends GrantedAuthority> getEntitlements(SAMLCredential credential, Object userDetail)
    {
        //logger.info("****** object is instance of UserDetails :"+ (userDetail instanceof UserDetails));

        if (userDetail instanceof UserDetails)
        {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.addAll(((UserDetails) userDetail).getAuthorities());
            return authorities;
        }
        else if(userDetail instanceof UsernamePasswordAuthenticationToken)
        {
            List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
            authorities.addAll(((UsernamePasswordAuthenticationToken) userDetail).getAuthorities());
            return authorities;

        } else {
            return Collections.emptyList();
        }
    }
}
