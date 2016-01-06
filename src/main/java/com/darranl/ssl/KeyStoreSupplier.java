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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.function.Supplier;

/**
 * A simple supplier of a {@link KeyStore}.
 *
 * @author <a href="mailto:darran.lofthouse@jboss.com">Darran Lofthouse</a>
 */
class KeyStoreSupplier implements Supplier<KeyStore> {

    private final String type;
    private final String path;
    private final char[] password;

    private KeyStoreSupplier(final String type, final String path, final char[] password) {
        this.type = type;
        this.path = path;
        this.password = password;
    }

    public KeyStore get() {
        try {
            KeyStore keyStore = KeyStore.getInstance(type);

            if (path != null) {
                try (FileInputStream fis = new FileInputStream(path)) {
                    keyStore.load(fis, password);
                }
            } else {
                keyStore.load(null, password);
            }

            return keyStore;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }

    }

    static Supplier<KeyStore> nullSupplier() {
        return () -> null;
    }

    static Builder builder() {
        return new Builder();
    }

    static class Builder {

        private String type = KeyStore.getDefaultType();
        private String path;
        private char[] password;

        Builder setType(final String type) {
            this.type = type;

            return this;
        }

        Builder setPath(final String path) {
            this.path = path;

            return this;
        }

        Builder setPassword(final char[] password) {
            this.password = password;

            return this;
        }

        Supplier<KeyStore> build() {
            return new KeyStoreSupplier(type, path, password);
        }

    }
}
