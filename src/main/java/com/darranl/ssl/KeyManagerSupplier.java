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

import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import java.util.function.Supplier;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509KeyManager;

/**
 *
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
public class KeyManagerSupplier implements Supplier<KeyManager[]> {

    private final String algorithm;
    private final Supplier<KeyStore> keyStoreSupplier;
    private final char[] password;
    private final String fixedAlias;

    private KeyManagerSupplier(String algorithm, Supplier<KeyStore> keyStoreSupplier, char[] password, final String fixedAlias) {
        this.algorithm = algorithm;
        this.keyStoreSupplier = keyStoreSupplier;
        this.password = password;
        this.fixedAlias = fixedAlias;
    }

    @Override
    public KeyManager[] get() {
        try {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
            keyManagerFactory.init(keyStoreSupplier.get(), password);

            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();
            for (int i = 0; i < keyManagers.length; i++) {
                if (keyManagers[i] instanceof X509KeyManager) {
                    X509KeyManager current = (X509KeyManager) keyManagers[i];
                    WrapperKeyManager wrapper = new WrapperKeyManager(current);
                    keyManagers[i] = wrapper;
                    if (current instanceof X509ExtendedKeyManager) {
                        keyManagers[i] = new ExtendedWrapperKeyManager(wrapper, (X509ExtendedKeyManager) current);
                    }
                }
            }

            return keyManagers;
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
        private String fixedAlias;

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

        Builder setFixedAlias(String fixedAlias) {
            this.fixedAlias = fixedAlias;

            return this;
        }

        Supplier<KeyManager[]> build() {
            return new KeyManagerSupplier(algorithm, keyStoreSupplier, password, fixedAlias);
        }

    }

    private class WrapperKeyManager implements X509KeyManager {

        private final X509KeyManager wrapped;

        WrapperKeyManager(X509KeyManager toWrap) {
            this.wrapped = toWrap;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return wrapped.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            String alias = wrapped.chooseServerAlias(keyType, issuers, socket);
            System.out.println(String.format("Alias '%s' chosen for keyType '%s'", alias, keyType));
            if (fixedAlias != null) {
                alias = fixedAlias;
                System.out.println(String.format("Alias overidden to '%s'", alias));
            }
            return alias;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return wrapped.getCertificateChain(alias);
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return wrapped.getClientAliases(keyType, issuers);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            PrivateKey privateKey = wrapped.getPrivateKey(alias);
            return privateKey;
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return wrapped.getServerAliases(keyType, issuers);
        }
    }

    private class ExtendedWrapperKeyManager extends X509ExtendedKeyManager {

        private final WrapperKeyManager wrapped;
        private final X509ExtendedKeyManager raw;

        ExtendedWrapperKeyManager(WrapperKeyManager wrapped, X509ExtendedKeyManager raw) {
            this.wrapped = wrapped;
            this.raw = raw;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return wrapped.chooseClientAlias(keyType, issuers, socket);
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return wrapped.chooseServerAlias(keyType, issuers, socket);
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return wrapped.getCertificateChain(alias);
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return wrapped.getClientAliases(keyType, issuers);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return wrapped.getPrivateKey(alias);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return wrapped.getServerAliases(keyType, issuers);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return raw.chooseEngineClientAlias(keyType, issuers, engine);
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return raw.chooseEngineServerAlias(keyType, issuers, engine);
        }

    }
}
