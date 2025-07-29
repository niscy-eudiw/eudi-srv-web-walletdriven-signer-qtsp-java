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

    public static final int DEFAULT = -1;

    public static final int SIGNATURE = 8;

    public static final int INTEGRITY = 9;

    private final int type;

    private final OID4VPEnumError error;

    public VerifiablePresentationVerificationException(OID4VPEnumError error, String message, int type) {
        super("Verification of the Verifiable Presentation Failed: " + message);

        if (type == SIGNATURE) {
            this.type = SIGNATURE;
        } else if (type == INTEGRITY) {
            this.type = INTEGRITY;
        } else
            this.type = DEFAULT;

        this.error = error;
    }

    public int getType() {
        return this.type;
    }

    public OID4VPEnumError getError() {
        return this.error;
    }
}