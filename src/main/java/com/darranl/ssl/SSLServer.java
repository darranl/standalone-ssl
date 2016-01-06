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
import java.net.Socket;
import java.util.function.Supplier;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

/**
 * Main entry point to open up a server socket for SSL connections.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SSLServer {

    private static final int DEFAULT_PORT = 2222;

    private final Supplier<SSLContext> sslContextSupplier;

    private SSLServer(Supplier<SSLContext> sslContextSupplier) {
        this.sslContextSupplier = sslContextSupplier;
    }

    private void run() throws IOException {
        SSLContext sslContext = sslContextSupplier.get();

        SSLServerSocketFactory serverSocketFactory = sslContext.getServerSocketFactory();

        SSLServerSocket serverSocket = (SSLServerSocket) serverSocketFactory.createServerSocket(DEFAULT_PORT);

        // TODO - Filter Cipher Suites

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
        for (String current : args) {
            port = Integer.parseInt(current);
        }

        SSLServer server = new SSLServer(SSLContextSupplier.builder()
                .setProtocol("TLSv1.2")
                .setKeyManagerSupplier(KeyManagerSupplier.builder()
                        .setAlgorithm("SunX509")
                        .setPassword("keystore_password".toCharArray())
                        .setKeyStoreSupplier(KeyStoreSupplier.builder()
                                .setType("JKS")
                                .setPath("rsa.keystore")
                                .setPassword("keystore_password".toCharArray())
                                .build())
                        .build())
                .build());

        server.run();
    }

}
