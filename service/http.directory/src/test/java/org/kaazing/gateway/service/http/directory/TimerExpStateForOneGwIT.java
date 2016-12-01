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

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.kaazing.gateway.server.test.GatewayClusterRule;
import org.kaazing.gateway.server.test.config.GatewayConfiguration;
import org.kaazing.gateway.server.test.config.builder.GatewayConfigurationBuilder;
import org.kaazing.k3po.junit.annotation.Specification;
import org.kaazing.k3po.junit.rules.K3poRule;
import org.kaazing.test.util.ResolutionTestUtils;

import java.io.File;
import java.util.concurrent.TimeUnit;

import static org.kaazing.test.util.ITUtil.createRuleChain;


public class TimerExpStateForOneGwIT {


    private final K3poRule robot = new K3poRule()
            .setScriptRoot("org/kaazing/specification/http/saml/auth");

    public GatewayRule gateway = new GatewayRule() {
        {
            GatewayConfiguration configuration = new GatewayConfigurationBuilder()
                .property(HTTP_REALM_ACCEPT_OPTION.getPropertyName(), "true")
                .service()
                  .type("directory")
                  .accept("http://localhost:8080/")
//                  .property("directory", "/public")
                  .crossOrigin()
				    .allowOrigin("*")
                  .done()
                  .property("welcome-file", "index.html")
                  .realmName("demo")
                    .authorization()
                      .requireRole("AUTHORIZED")
                    .done()
                .done()
                .security()
                    .realm()
                        .name("demo")
                        .description("demo")
                        .httpChallengeScheme("Basic")
                        .authorizationMode("challenge")
                        .loginModule()
                            .type("class:org.kaazing.gateway.service.http.directory.ExpiringTokenCustomLoginModule")
                            .success("required")
                        .done()
                    .done()
                .done()
            .done();
            init(configuration);
        }
    };

    @Rule
    public TestRule chain = createRuleChain(gateway, robot);

    @Specification("expState.challenge.rejected.then.accepted")
    @Test
    public void expStateTimer30sec() throws Exception {
        robot.finish();
    }
	

}