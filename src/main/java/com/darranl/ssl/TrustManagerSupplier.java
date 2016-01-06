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

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class TrustManagerSupplier implements Supplier<TrustManager[]> {

    private final String algorithm;
    private final Supplier<KeyStore> keyStoreSupplier;

    private TrustManagerSupplier(String algorithm, Supplier<KeyStore> keyStoreSupplier) {
        this.algorithm = algorithm;
        this.keyStoreSupplier = keyStoreSupplier;
    }

    @Override
    public TrustManager[] get() {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(algorithm);
            trustManagerFactory.init(keyStoreSupplier.get());

            return trustManagerFactory.getTrustManagers();
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    static Supplier<TrustManager[]> nullSupplier() {
        return () -> null;
    }

    static Supplier<TrustManager[]> trustingSupplier() {
        return new Supplier<TrustManager[]>() {

            @Override
            public TrustManager[] get() {
                TrustManager[] trustManagers = new TrustManager[1];
                trustManagers[0] = new X509TrustManager() {

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                    }
                };
                return trustManagers;
            }
        };
    }

    static Builder builder() {
        return new Builder();
    }

    static class Builder {
        private String algorithm = TrustManagerFactory.getDefaultAlgorithm();
        private Supplier<KeyStore> keyStoreSupplier = KeyStoreSupplier.nullSupplier();

        Builder setAlgorithm(String algorithm) {
            this.algorithm = algorithm;

            return this;
        }

        Builder setKeyStoreSupplier(Supplier<KeyStore> keyStoreSupplier) {
            this.keyStoreSupplier = keyStoreSupplier;

            return this;
        }

        Supplier<TrustManager[]> build() {
            return new TrustManagerSupplier(algorithm, keyStoreSupplier);
        }
    }

}
