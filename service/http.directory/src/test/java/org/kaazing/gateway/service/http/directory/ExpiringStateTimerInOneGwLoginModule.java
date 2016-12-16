
/**
 * Copyright 2007-2016, Kaazing Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.kaazing.gateway.service.http.directory;

import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.FailedLoginException;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;


import org.kaazing.gateway.security.auth.config.JaasConfig;
import org.kaazing.gateway.security.auth.config.RoleConfig;
import org.kaazing.gateway.security.auth.config.UserConfig;
import org.kaazing.gateway.security.auth.config.parse.DefaultUserConfig;
import org.kaazing.gateway.security.auth.config.parse.JaasConfigParser;
import org.kaazing.gateway.server.ExpiringState;
import org.kaazing.gateway.server.spi.security.AuthenticationToken;
import org.kaazing.gateway.server.spi.security.AuthenticationTokenCallback;
import org.kaazing.gateway.server.spi.security.LoginResult;
import org.kaazing.gateway.server.spi.security.LoginResultCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExpiringStateTimerInOneGwLoginModule implements LoginModule {

    public static final String CLASS_NAME = ExpiringStateTimerInOneGwLoginModule.class.getName();
    public static final String LOG_PREFIX = "[LM] ";
    public static final Logger logger = LoggerFactory.getLogger(CLASS_NAME);
    private static final String NUMBER_OF_ATTEMPTS_KEY = "NUMBER_OF_ATTEMPTS";
    private static final String LOGGED_IN = "LOGGED_IN";


    private static final String TEST_PRINCIPAL_PASS = "testPrincipalPass";
    private static final String TEST_PRINCIPAL_NAME = "testPrincipalName";
    private DefaultUserConfig defaultPrincipal = new DefaultUserConfig();

    private ExpiringState expiringState;

    // initial state
    protected Subject subject;
    private Map<String, ?> sharedState;

    // the authentication status
    private boolean succeeded;
    private boolean commitSucceeded;

    // testUser's RolePrincipal
    private RolePrincipal userPrincipal;

    @Override
    public void initialize(Subject subject,
                           CallbackHandler callbackHandler,
                           Map<String, ?> sharedState,
                           Map<String, ?> options) {

        expiringState = (ExpiringState) options.get("ExpiringState");
        this.subject = subject;
        this.sharedState = sharedState;
    }

    private void logDebug(String message) {
        logger.debug(LOG_PREFIX + message);
    }


    @Override
    public boolean login() throws LoginException {
        // verify the username/password
        String username = (String) sharedState.get("javax.security.auth.login.name");
        char[] password = (char[]) sharedState.get("javax.security.auth.login.password");

        for (String s : sharedState.keySet()) {
            logDebug("key: " + s);
        }

        if (username == null || password == null) {
            throw new FailedLoginException("No UserName/Password to authenticate");
        }
        String strPass = new String(password);
        logDebug("Username: " + username);
        logDebug("Password: " + strPass);

        Boolean loggedIn = (Boolean) expiringState.get(LOGGED_IN);
        logDebug("loggedIn: " + loggedIn);
        if (loggedIn != null && loggedIn == true) {
            succeeded = true;
            return true;
        }
        if ("joe".equals(username) && "welcome12".equals(strPass)) {
            logDebug("login successful");
            // pass login send 200
            // TO CONFIRM I think you return true
            expiringState.putIfAbsent(LOGGED_IN, true, 30, TimeUnit.SECONDS);
            succeeded = true;
            return true;
        }
        logDebug("login failed");
        succeeded = false;
        return false;

    }

    @Override
    public boolean commit() throws LoginException {
        if (!succeeded) {
            return false;
        } else {
            // add a Principal (authenticated identity) to the Subject
            userPrincipal = new RolePrincipal("AUTHORIZED");
            subject.getPrincipals().add(userPrincipal);
            commitSucceeded = true;

            defaultPrincipal.setName(TEST_PRINCIPAL_NAME);
            defaultPrincipal.setPassword(TEST_PRINCIPAL_PASS);
            subject.getPrincipals().add(defaultPrincipal);

            return true;
        }
    }

    @Override
    public boolean abort() throws LoginException {
        if (!succeeded) {
            return false;
        } else if (!commitSucceeded) {
            // login succeeded but overall authentication failed
            succeeded = false;
            userPrincipal = null;
        } else {
            // overall authentication succeeded and commit succeeded,
            // but someone else's commit failed
            logout();
        }
        return true;
    }

    @Override
    public boolean logout() throws LoginException {
        subject.getPrincipals().remove(userPrincipal);
        succeeded = false;
        commitSucceeded = false;
        userPrincipal = null;
        subject.getPrincipals().remove(defaultPrincipal);
        return true;
    }

    private static class RolePrincipal implements Principal {

        private final String name;

        public RolePrincipal(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public String toString() {
            return "Role:  " + name;
        }

        @Override
        public boolean equals(Object o) {
            if (o == null) {
                return false;
            }
            if (this == o) {
                return true;
            }
            if (!(o instanceof RolePrincipal)) {
                return false;
            }
            RolePrincipal that = (RolePrincipal) o;

            return this.getName().equals(that.getName());
        }

        @Override
        public int hashCode() {
            return name.hashCode();
        }
    }

}