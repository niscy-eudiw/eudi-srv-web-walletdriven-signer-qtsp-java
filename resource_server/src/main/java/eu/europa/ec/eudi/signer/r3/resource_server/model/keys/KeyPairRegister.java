/*
 Copyright 2024 European Commission

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      https://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

package eu.europa.ec.eudi.signer.r3.resource_server.model.keys;

import java.security.PublicKey;

public class KeyPairRegister {
    private byte[] privateKeyBytes;
    private PublicKey publicKeyValue;

    public KeyPairRegister(){
        this.privateKeyBytes = null;
        this.publicKeyValue = null;
    }

    public KeyPairRegister(byte[] privateKeyBytes, PublicKey publicKey){
        this.privateKeyBytes = privateKeyBytes;
        this.publicKeyValue = publicKey;
    }

    public byte[] getPrivateKeyBytes() {
        return privateKeyBytes;
    }

    public void setPrivateKeyBytes(byte[] privateKeyBytes) {
        this.privateKeyBytes = privateKeyBytes;
    }

    public PublicKey getPublicKeyValue() {
        return publicKeyValue;
    }

    public void setPublicKeyValue(PublicKey publicKeyValue) {
        this.publicKeyValue = publicKeyValue;
    }
}
