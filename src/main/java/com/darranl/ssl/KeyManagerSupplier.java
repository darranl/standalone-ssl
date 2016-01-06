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
import java.security.UnrecoverableKeyException;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KeyManagerSupplier implements Supplier<KeyManager[]> {

    private final String algorithm;
    private final Supplier<KeyStore> keyStoreSupplier;
    private final char[] password;

    private KeyManagerSupplier(String algorithm, Supplier<KeyStore> keyStoreSupplier, char[] password) {
        this.algorithm = algorithm;
        this.keyStoreSupplier = keyStoreSupplier;
        this.password = password;
    }

    @Override
    public KeyManager[] get() {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
            keyManagerFactory.init(keyStoreSupplier.get(), password);

            return keyManagerFactory.getKeyManagers();
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            throw new IllegalStateException(e);
        }
    }

    static Supplier<KeyManager[]> nullSupplier() {
        return () -> null;
    }

    static Builder builder() {
        return new Builder();
    }

    static class Builder {

        private String algorithm = KeyManagerFactory.getDefaultAlgorithm();
        private Supplier<KeyStore> keyStoreSupplier = KeyStoreSupplier.nullSupplier();
        private char[] password;

        Builder setAlgorithm(String algorithm) {
            this.algorithm = algorithm;

            return this;
        }

        Builder setKeyStoreSupplier(Supplier<KeyStore> keyStoreSupplier) {
            this.keyStoreSupplier = keyStoreSupplier;

            return this;
        }

        Builder setPassword(char[] password) {
            this.password = password;

            return this;
        }

        Supplier<KeyManager[]> build() {
            return new KeyManagerSupplier(algorithm, keyStoreSupplier, password);
        }

    }

}
