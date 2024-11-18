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

package eu.europa.ec.eudi.signer.r3.authorization_server.model.exception;


public class VerifiablePresentationVerificationException extends Exception {

    public static final int Default = -1;

    public static final int Signature = 8;

    public static final int Integrity = 9;

    private final int type;

    private final SignerError error;

    public VerifiablePresentationVerificationException(SignerError error, String message, int type) {
        super("Verification of the Verifiable Presentation Failed: " + message);

        if (type == Signature) {
            this.type = Signature;
        } else if (type == Integrity) {
            this.type = Integrity;
        } else
            this.type = Default;

        this.error = error;
    }

    public int getType() {
        return this.type;
    }

    public SignerError getError() {
        return this.error;
    }
}