/*
 * Copyright (c) 2014 AsyncHttpClient Project. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */
package org.asynchttpclient.providers.grizzly.filters;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import org.glassfish.grizzly.ssl.SSLEngineConfigurator;

public class HostPortAwareSSLEngineConfigurator extends SSLEngineConfigurator {

    public HostPortAwareSSLEngineConfigurator(final SSLContext context, final boolean clientMode, final boolean needClientAuth,
            final boolean wantClientAuth) {
        super(context, clientMode, needClientAuth, wantClientAuth);
    }

    /**
     * Create and configure {@link SSLEngine} using this context configuration
     * using advisory peer information.
     * <P>
     * Applications using this factory method are providing hints
     * for an internal session reuse strategy.
     * <P>
     * Some cipher suites (such as Kerberos) require remote hostname
     * information, in which case peerHost needs to be specified.
     * 
     * @param   peerHost the non-authoritative name of the host
     * @param   peerPort the non-authoritative port
     * 
     * @return {@link SSLEngine}.
     */
    public SSLEngine createSSLEngine(final String peerHost, final int peerPort) {
        final SSLEngine sslEngine = getSslContext().createSSLEngine(peerHost, peerPort);
        configure(sslEngine);

        return sslEngine;
    }
}