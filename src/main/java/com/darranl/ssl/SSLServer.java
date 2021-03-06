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

import java.io.IOException;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.wildfly.security.ssl.CipherSuiteSelector;

/**
 * Main entry point to open up a server socket for SSL connections.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SSLServer {

    private static final int DEFAULT_PORT = 2222;

    private final int port;
    private final String ciphers;
    private final Supplier<SSLContext> sslContextSupplier;

    private SSLServer(int port, String ciphers, Supplier<SSLContext> sslContextSupplier) {
        this.port = port;
        this.ciphers = ciphers;
        this.sslContextSupplier = sslContextSupplier;
    }

    private void run() throws IOException {
        SSLContext sslContext = sslContextSupplier.get();

        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(port);

        if (ciphers != null && ciphers.length() > 0) {
            CipherSuiteSelector cipherSuiteSelector = CipherSuiteSelector.fromString(ciphers);
            String[] enabledCiphers = cipherSuiteSelector.evaluate(serverSocket.getSupportedCipherSuites());
            StringBuilder sb = new StringBuilder("{");
            for (int i = 0; i < enabledCiphers.length; i++) {
                if (i > 0) {
                    sb.append(", ");
                }
                sb.append(enabledCiphers[i]);
            }
            sb.append("}");
            System.out.println(String.format("Enabled Ciphers '%s'", sb.toString()));
            serverSocket.setEnabledCipherSuites(enabledCiphers);
        }

        while (true) {
            System.out.println("Waiting for a client");
            SSLSocket client = (SSLSocket) serverSocket.accept();

            System.out.println(String.format("Have a connection from '%s' valid SSL Session '%b' selected cipher '%s'", client.getInetAddress().getHostAddress(), client.getSession().isValid(), client.getSession().getCipherSuite()));

            client.close();
        }
    }

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {
        int port = DEFAULT_PORT;
        String ciphers = null;
        String keystore = "rsa.keystore";
        String password = "keystore_password";
        String fixedAlias = null;
        for (String current : args) {
            if (current.startsWith("ciphers=")) {
                ciphers = current.substring(8);
            } else if (current.startsWith("fixed-alias=")) {
                String temp = current.substring(12);
                if (temp.length() > 0) {
                    fixedAlias = temp;
                }
            } else if (current.startsWith("keystore=")) {
                keystore = current.substring(9);
            } else if (current.startsWith("password=")) {
                password = current.substring(9);
            } else if (current.startsWith("port=")) {
                port = Integer.parseInt(current.substring(5));
            }
        }

        SSLServer server = new SSLServer(port, ciphers, SSLContextSupplier.builder()
                .setProtocol("TLSv1.2")
                .setKeyManagerSupplier(KeyManagerSupplier.builder()
                        .setAlgorithm("SunX509")
                        .setPassword(password.toCharArray())
                        .setFixedAlias(fixedAlias)
                        .setKeyStoreSupplier(KeyStoreSupplier.builder()
                                .setType("JKS")
                                .setPath(keystore)
                                .setPassword(password.toCharArray())
                                .build())
                        .build())
                .build());

        server.run();
    }

}
