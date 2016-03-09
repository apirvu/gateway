/**
 * Copyright 2007-2015, Kaazing Corporation. All rights reserved.
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
package org.kaazing.gateway.service.http.proxy;

import static org.kaazing.gateway.transport.http.HttpHeaders.HEADER_CONNECTION;
import static org.kaazing.gateway.transport.http.HttpHeaders.HEADER_LOCATION;
import static org.kaazing.gateway.transport.http.HttpHeaders.HEADER_SET_COOKIE;
import static org.kaazing.gateway.transport.http.HttpHeaders.HEADER_UPGRADE;
import static org.kaazing.gateway.transport.http.HttpHeaders.HEADER_VIA;
import static org.kaazing.gateway.transport.http.HttpStatus.CLIENT_NOT_FOUND;
import static org.kaazing.gateway.transport.http.HttpStatus.INFO_SWITCHING_PROTOCOLS;

import java.net.URI;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import org.apache.mina.core.future.CloseFuture;
import org.apache.mina.core.future.ConnectFuture;
import org.apache.mina.core.future.IoFutureListener;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.core.session.IoSessionInitializer;
import org.kaazing.gateway.resource.address.ResourceAddress;
import org.kaazing.gateway.resource.address.http.HttpResourceAddress;
import org.kaazing.gateway.service.ServiceContext;
import org.kaazing.gateway.service.ServiceProperties;
import org.kaazing.gateway.service.proxy.AbstractProxyAcceptHandler;
import org.kaazing.gateway.service.proxy.AbstractProxyHandler;
import org.kaazing.gateway.transport.IoHandlerAdapter;
import org.kaazing.gateway.transport.http.DefaultHttpSession;
import org.kaazing.gateway.transport.http.HttpAcceptSession;
import org.kaazing.gateway.transport.http.HttpConnectSession;
import org.kaazing.gateway.transport.http.HttpSession;
import org.kaazing.gateway.transport.http.HttpStatus;
import org.kaazing.mina.core.session.IoSessionEx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class HttpProxyServiceHandler extends AbstractProxyAcceptHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger("service.http.proxy");
    
    private static final String VIA_HEADER_VALUE = "1.1 kaazing";

    private static final Set KNOWN_SIMPLE_PROPERTIES;
    static {
        Set<String> set = new HashSet<>();
        set.add("rewrite-cookie-domain");
        set.add("rewrite-cookie-path");
        set.add("rewrite-location");
        KNOWN_SIMPLE_PROPERTIES = Collections.unmodifiableSet(set);
    }

    private static final Set KNOWN_NESTED_PROPERTIES;
    static {
        Set<String> set = new HashSet<>();
        set.add("cookie-domain-mapping");
        set.add("cookie-path-mapping");
        set.add("location-mapping");
        KNOWN_NESTED_PROPERTIES = Collections.unmodifiableSet(set);
    }


    private String connectURI;
    private boolean rewriteCookieDomain;
    private boolean rewriteCookiePath;
    private boolean rewriteLocation;
    private Map<String, String> cookieDomainMap;
    private Map<String, String> cookiePathMap;
    private Map<String, String> locationMap;

    void init() {
        ServiceContext serviceContext = getServiceContext();

        Collection<String> acceptURIs = serviceContext.getAccepts();
        Collection<String> connectURIs = serviceContext.getConnects();

        String acceptURI = acceptURIs.iterator().next();
        connectURI = connectURIs.iterator().next();

        validateProperties(serviceContext);

        ServiceProperties properties = serviceContext.getProperties();

        rewriteCookieDomain = "enabled".equals(properties.get("rewrite-cookie-domain"));
        rewriteCookiePath = "enabled".equals(properties.get("rewrite-cookie-path"));
        rewriteLocation = !"disabled".equals(properties.get("rewrite-location"));

        cookieDomainMap = new HashMap<>();
        if (rewriteCookieDomain) {
            List<ServiceProperties> cookieDomainProperties = properties.getNested("cookie-domain-mapping");
            for (ServiceProperties sp : cookieDomainProperties) {
                cookieDomainMap.put(sp.get("from"), sp.get("to"));
            }
        }

        cookiePathMap = new HashMap<>();
        if (rewriteCookiePath) {
            List<ServiceProperties> cookiePathProperties = properties.getNested("cookie-path-mapping");
            for (ServiceProperties sp : cookiePathProperties) {
                cookiePathMap.put(sp.get("from"), sp.get("to"));
            }
        }

        locationMap = new HashMap<>();
        if (rewriteLocation) {
            List<ServiceProperties> locationProperties = properties.getNested("location-mapping");
            for (ServiceProperties sp : locationProperties) {
                locationMap.put(sp.get("from"), sp.get("to"));
            }
            locationMap.put(connectURI.toString(), acceptURI.toString());
        }
    }

    private void validateProperties(ServiceContext serviceContext) {
        ServiceProperties properties = serviceContext.getProperties();

        // validate all properties: rewrite-cookie-domain, rewrite-cookie-path, rewrite-location
        Iterable<String> simpleProperties = properties.simplePropertyNames();
        Set<String> unknownProperties = StreamSupport.stream(simpleProperties.spliterator(), false)
                .filter(p -> !KNOWN_SIMPLE_PROPERTIES.contains(p))
                .collect(Collectors.toSet());
        Iterable<String> nestedProperties = properties.nestedPropertyNames();
        StreamSupport.stream(nestedProperties.spliterator(), false)
                .filter(p -> !KNOWN_NESTED_PROPERTIES.contains(p))
                .forEach(unknownProperties::add);
        if (!unknownProperties.isEmpty()) {
            throw new IllegalArgumentException(serviceContext.getServiceName() +
                    " http.proxy service specifies unknown properties : " + unknownProperties);
        }
    }

    @Override
    protected AbstractProxyHandler createConnectHandler() {
        return new ConnectHandler();
    }

    @Override
    public void sessionOpened(IoSession session) {
        if (!session.isClosing()) {
            final DefaultHttpSession acceptSession = (DefaultHttpSession) session;
            //final Subject subject = ((IoSessionEx) acceptSession).getSubject();

            if (!validateRequestPath(acceptSession)) {
                acceptSession.setStatus(CLIENT_NOT_FOUND);
                acceptSession.close(false);
                return;
            }

            ConnectSessionInitializer sessionInitializer = new ConnectSessionInitializer(acceptSession);
            ConnectFuture future = getServiceContext().connect(connectURI, getConnectHandler(), sessionInitializer);
            future.addListener(new ConnectListener(acceptSession));
            super.sessionOpened(acceptSession);
        }
    }

    private boolean validateRequestPath(DefaultHttpSession acceptSession) {
        URI requestURI = acceptSession.getRequestURI();
        String acceptPath = acceptSession.getServicePath().getPath();
        String requestPath = requestURI.normalize().getPath();

        return requestPath.startsWith(acceptPath);
    }

    /*
     * Initializer for connect session. It adds the processed accept session headers
     * on the connect session
     */
    private static class ConnectSessionInitializer implements IoSessionInitializer<ConnectFuture> {
        private final DefaultHttpSession acceptSession;

        ConnectSessionInitializer(DefaultHttpSession acceptSession) {
            this.acceptSession = acceptSession;
        }

        @Override
        public void initializeSession(IoSession session, ConnectFuture future) {
            HttpConnectSession connectSession = (HttpConnectSession) session;
            connectSession.setVersion(acceptSession.getVersion());
            connectSession.setMethod(acceptSession.getMethod());
            URI connectURI = computeConnectPath(connectSession.getRequestURI());
            connectSession.setRequestURI(connectURI);
            processRequestHeaders(acceptSession, connectSession);
        }

        private URI computeConnectPath(URI connectURI) {
            String acceptPath = acceptSession.getServicePath().getPath();
            String requestUri = acceptSession.getRequestURI().toString();
            String connectPath = connectURI.getPath();
            return URI.create(connectPath + requestUri.substring(acceptPath.length()));
        }

    }

    private class ConnectListener implements IoFutureListener<ConnectFuture> {
        private final DefaultHttpSession acceptSession;

        ConnectListener(DefaultHttpSession acceptSession) {
            this.acceptSession = acceptSession;
        }

        @Override
        public void operationComplete(ConnectFuture future) {
            if (future.isConnected()) {
                DefaultHttpSession connectSession = (DefaultHttpSession)future.getSession();

                if (LOGGER.isTraceEnabled()) {
                    LOGGER.trace("Connected to " + getConnectURIs().iterator().next() + " ["+acceptSession+"->"+connectSession+"]");
                }
                if (acceptSession == null || acceptSession.isClosing()) {
                    connectSession.close(true);
                } else {
                    AttachedSessionManager attachedSessionManager = attachSessions(acceptSession, connectSession);
                    connectSession.getCloseFuture().addListener(new Upgrader(connectSession, acceptSession));
                    acceptSession.getCloseFuture().addListener(new Upgrader(acceptSession, connectSession));
                    flushQueuedMessages(acceptSession, attachedSessionManager);
                }
            } else {
                LOGGER.warn("Connection to " + getConnectURIs().iterator().next() + " failed ["+acceptSession+"->]");
                acceptSession.setStatus(HttpStatus.SERVER_GATEWAY_TIMEOUT);
                acceptSession.close(true);
            }
        }

    }

    private class ConnectHandler extends AbstractProxyHandler {

        @Override
        public void messageReceived(IoSession session, Object message) {
            processResponseHeaders(session);
            super.messageReceived(session, message);
        }

        @Override
        public void sessionClosed(IoSession session) {
            processResponseHeaders(session);
            super.sessionClosed(session);
        }

        private void processResponseHeaders(IoSession session) {
            HttpConnectSession connectSession = (HttpConnectSession) session;
            AttachedSessionManager attachedSessionManager = getAttachedSessionManager(session);
            if (attachedSessionManager != null) {
                HttpAcceptSession acceptSession = (HttpAcceptSession) attachedSessionManager.getAttachedSession();
                if (acceptSession.getWrittenBytes() == 0L && !acceptSession.isCommitting() && !acceptSession.isClosing()) {
                    acceptSession.setStatus(connectSession.getStatus());
                    acceptSession.setReason(connectSession.getReason());
                    acceptSession.setVersion(connectSession.getVersion());

                    processResponseHeaders(connectSession, acceptSession);
                }

            }
        }

        private void processResponseHeaders(HttpSession connectSession, HttpSession acceptSession) {

            Set<String> hopByHopHeaders = getHopByHopHeaders(connectSession);
            boolean upgrade = connectSession.getReadHeader(HEADER_UPGRADE) != null;
            if (upgrade) {
                hopByHopHeaders.remove(HEADER_UPGRADE);
            }

            // Add processed connect session headers to accept session
            for (Map.Entry<String, List<String>> e : connectSession.getReadHeaders().entrySet()) {
                String name = e.getKey();
                // don't add hop-by-hop response headers
                if (hopByHopHeaders.contains(name)) {
                    continue;
                }
                for (String value : e.getValue()) {
                    if (name.equalsIgnoreCase(HEADER_SET_COOKIE)) {
                        if (rewriteCookieDomain) {
                            value = processCookieDomain(value, cookieDomainMap);
                        }
                        if (rewriteCookiePath) {
                            value = processCookiePath(value, cookiePathMap);
                        }
                        acceptSession.addWriteHeader(name, value);
                    } else if (name.equalsIgnoreCase(HEADER_LOCATION)) {
                        if (rewriteLocation) {
                            value = processLocationHeader(value, locationMap);
                        }
                        acceptSession.addWriteHeader(name, value);
                    } else {
                        acceptSession.addWriteHeader(name ,value);
                    }
                }
            }

            // Add Connection: upgrade to acceptSession
            if (upgrade) {
                acceptSession.setWriteHeader(HEADER_CONNECTION, HEADER_UPGRADE);
            }

        }

        private String processCookieDomain(String cookie, Map<String, String> cookieDomainMap) {
            String lowerCookie = cookie.toLowerCase();
            if (lowerCookie.contains("domain=")) {
                return cookieDomainMap.entrySet().stream()
                        .filter(e -> lowerCookie.contains("domain="+e.getKey()))
                        .findFirst()
                        .map(e -> {
                            int index = lowerCookie.indexOf("domain="+e.getKey());
                            return cookie.substring(0, index+7)+e.getValue()+cookie.substring(index+7+e.getKey().length());
                        })
                        .orElse(cookie);
            }
            return cookie;
        }

        private String processCookiePath(String cookie, Map<String, String> cookiePathMap) {
            String lowerCookie = cookie.toLowerCase();
            if (lowerCookie.contains("path=")) {
                return cookiePathMap.entrySet().stream()
                        .filter(e -> lowerCookie.contains("path="+e.getKey()))
                        .findFirst()
                        .map(e -> {
                            int index = lowerCookie.indexOf("path="+e.getKey());
                            return cookie.substring(0, index+5)+e.getValue()+cookie.substring(index+5+e.getKey().length());
                        })
                        .orElse(cookie);
            }
            return cookie;
        }

        private String processLocationHeader(String location, Map<String, String> locationMap) {
            return locationMap.entrySet().stream()
                    .filter(e -> location.startsWith(e.getKey()))
                    .findFirst()
                    .map(e -> location.replaceFirst(Pattern.quote(e.getKey()), e.getValue()))
                    .orElse(location);
        }

    }


    /*
     * Write all (except hop-by-hop) headers from source session to destination session.
     *
     * If the header is an upgrade one, let the Upgrade header go through as this service supports upgrade
     */
    private static boolean processHopByHopHeaders(HttpSession src, HttpSession dest) {
        Set<String> hopByHopHeaders = getHopByHopHeaders(src);
        boolean upgrade = src.getReadHeader(HEADER_UPGRADE) != null;
        if (upgrade) {
            hopByHopHeaders.remove(HEADER_UPGRADE);
        }

        // Add source session headers to destination session
        for (Map.Entry<String, List<String>> e : src.getReadHeaders().entrySet()) {
            String name = e.getKey();
            for (String value : e.getValue()) {
                if (!hopByHopHeaders.contains(name)) {
                    dest.addWriteHeader(name, value);
                }
            }
        }

        return upgrade;
    }

    /*
     * Write all (except hop-by-hop) request headers from accept session to connect session. If the request is an
     * upgrade one, let the Upgrade header go through as this service supports upgrade
     */
    private static void processRequestHeaders(HttpAcceptSession acceptSession, HttpConnectSession connectSession) {
        boolean upgrade = processHopByHopHeaders(acceptSession, connectSession);

        // Add Connection: upgrade or Connection: close header
        if (upgrade) {
            connectSession.setWriteHeader(HEADER_CONNECTION, HEADER_UPGRADE);
        } else {
            ResourceAddress address = connectSession.getRemoteAddress();
            // If keep-alive is disabled, add Connection: close header
            if (!address.getOption(HttpResourceAddress.KEEP_ALIVE)) {
                connectSession.setWriteHeader(HEADER_CONNECTION, "close");
            }
        }

        // Add Via: 1.1 kaazing header
        connectSession.addWriteHeader(HEADER_VIA, VIA_HEADER_VALUE);
    }
    
    /*
     * Get all hop-by-hop headers from Connection header value.
     * Also add Connection header itself to the set
     */
    private static Set<String> getHopByHopHeaders(HttpSession session) {
        List<String> connectionHeaders = session.getReadHeaders(HEADER_CONNECTION);
        if (connectionHeaders == null) {
            connectionHeaders = Collections.emptyList();
        }
        Set<String> hopByHopHeaders = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for(String conHeader : connectionHeaders) {
            hopByHopHeaders.add(conHeader);
        }
        hopByHopHeaders.add(HEADER_CONNECTION);
        return hopByHopHeaders;
    }

    /*
     * An upgrade handler that connects transport sessions of http accept and connect
     * sessions.
     */
    private static class ProxyUpgradeHandler extends IoHandlerAdapter<IoSessionEx>  {
        final IoSession attachedSession;

        ProxyUpgradeHandler(IoSession attachedSession) {
            this.attachedSession = attachedSession;
        }

        @Override
        protected void doSessionOpened(final IoSessionEx session) throws Exception {
            session.resumeRead();
        }

        @Override
        protected void doMessageReceived(IoSessionEx session, Object message) throws Exception {
            attachedSession.write(message);
        }

        @Override
        protected void doExceptionCaught(IoSessionEx session, Throwable cause) throws Exception {
            attachedSession.close(false);
        }

        @Override
        protected void doSessionClosed(IoSessionEx session) throws Exception {
            attachedSession.close(false);
        }

    }

    /*
     * A close listener that upgrades underlying transport connection
     * at the end of http session close.
     */
    private static class Upgrader implements IoFutureListener<CloseFuture> {
        private final DefaultHttpSession session;
        private final DefaultHttpSession attachedSession;

        Upgrader(DefaultHttpSession session, DefaultHttpSession attachedSession) {
            this.session = session;
            this.attachedSession = attachedSession;
        }

        @Override
        public void operationComplete(CloseFuture future) {
            if (session.getStatus() == INFO_SWITCHING_PROTOCOLS) {
                ProxyUpgradeHandler handler = new ProxyUpgradeHandler(attachedSession.getParent());
                session.suspendRead();
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(String.format("http.proxy service is upgrading session %s", session));
                }
                session.upgrade(handler);
            }
        }
    }

}
