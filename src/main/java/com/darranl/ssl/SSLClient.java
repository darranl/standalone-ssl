/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.darranl.ssl;

import java.net.InetSocketAddress;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.wildfly.security.ssl.CipherSuiteSelector;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SSLClient {

    private static final int DEFAULT_PORT = 2222;

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {
        int port = DEFAULT_PORT;
        String ciphers = null;
        for (String current : args) {
            if (current.startsWith("ciphers=")) {
                ciphers = current.substring(8);
            } else if (current.startsWith("port=")) {
                port = Integer.parseInt(current.substring(5));
            }
        }


        System.out.println("Client Started");

        SSLContext sslContext = SSLContextSupplier.builder()
                .setProtocol("TLSv1.2")
                .setTrustManagerSupplier(TrustManagerSupplier.trustingSupplier())
                .build()
                .get();

        SSLSocketFactory socketFactory = sslContext.getSocketFactory();

        SSLSocket socket = (SSLSocket) socketFactory.createSocket();
        if (ciphers != null && ciphers.length() > 0) {
            CipherSuiteSelector cipherSuiteSelector = CipherSuiteSelector.fromString(ciphers);
            String[] enabledCiphers = cipherSuiteSelector.evaluate(socketFactory.getSupportedCipherSuites());
            StringBuilder sb = new StringBuilder("{");
            for (int i = 0; i < enabledCiphers.length; i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(enabledCiphers[i]);
            }
            sb.append("}");
            System.out.println(String.format("Enabled Ciphers '%s'", sb.toString()));
            socket.setEnabledCipherSuites(enabledCiphers);
        }

        socket.connect(new InetSocketAddress("localhost", port), 5000);

        System.out.println(String.format("Have a connection to '%s' valid SSL Session '%b' selected cipher '%s'", socket.getInetAddress().getHostAddress(), socket.getSession().isValid(), socket.getSession().getCipherSuite()));

        socket.close();
    }

}
