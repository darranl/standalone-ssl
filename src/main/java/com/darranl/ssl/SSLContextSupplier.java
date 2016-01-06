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

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class SSLContextSupplier implements Supplier<SSLContext> {

    private final String protocol;
    private final Supplier<KeyManager[]> keyManagerSupplier;
    private final Supplier<TrustManager[]> trustManagerSupplier;
    private final Supplier<SecureRandom> secureRandomSupplier;

    SSLContextSupplier(String protocol, Supplier<KeyManager[]> keyManagerSupplier, Supplier<TrustManager[]> trustManagerSupplier, Supplier<SecureRandom> secureRandomSupplier) {
        this.protocol = protocol;
        this.keyManagerSupplier = keyManagerSupplier;
        this.trustManagerSupplier = trustManagerSupplier;
        this.secureRandomSupplier = secureRandomSupplier;
    }

    @Override
    public SSLContext get() {
        try {
            SSLContext sslContext = SSLContext.getInstance(protocol);

            sslContext.init(keyManagerSupplier.get(), trustManagerSupplier.get(), secureRandomSupplier.get());
            return sslContext;
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new IllegalStateException(e);
        }
    }

    static Builder builder() {
        return new Builder();
    }

    static class Builder {
        private String protocol;
        private Supplier<KeyManager[]> keyManagerSupplier = KeyManagerSupplier.nullSupplier();
        private Supplier<TrustManager[]> trustManagerSupplier = TrustManagerSupplier.nullSupplier();
        private Supplier<SecureRandom> secureRandomSupplier = SecureRandomSupplier.nullSupplier();

        Builder setProtocol(final String protocol) {
            this.protocol = protocol;

            return this;
        }

        Builder setKeyManagerSupplier(Supplier<KeyManager[]> keyManagerSupplier) {
            this.keyManagerSupplier = keyManagerSupplier;

            return this;
        }

        Builder setTrustManagerSupplier(Supplier<TrustManager[]> trustManagerSupplier) {
            this.trustManagerSupplier = trustManagerSupplier;

            return this;
        }

        Builder setSecureRandomSupplier(Supplier<SecureRandom> secureRandomSupplier) {
            this.secureRandomSupplier = secureRandomSupplier;

            return this;
        }

        Supplier<SSLContext> build() {
            return new SSLContextSupplier(protocol, keyManagerSupplier, trustManagerSupplier, secureRandomSupplier);
        }
    }

}
