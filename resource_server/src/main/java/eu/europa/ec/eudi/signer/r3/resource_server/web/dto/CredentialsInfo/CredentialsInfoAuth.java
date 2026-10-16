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

package eu.europa.ec.eudi.signer.r3.resource_server.web.dto.CredentialsInfo;

import java.util.List;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

@Schema(description = "Authorization mode of the credential. Only returned if `authInfo` is `true`.")
public class CredentialsInfoAuth {
    @NotBlank
    @Schema(description = "How the credential is authorized: with explicit authentication objects, or with an "
            + "OAuth 2.0 authorization code.", allowableValues = {"explicit", "oauth2code"})
    private String mode;
    @Schema(description = "Expression combining the authentication `objects`. Only for the `explicit` mode.")
    private String expression;
    @Schema(description = "Authentication objects required to authorize the credential. Only for the `explicit` "
            + "mode.")
    private List<Object> objects;

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public String getExpression() {
        return expression;
    }

    public void setExpression(String expression) {
        this.expression = expression;
    }

    public List<Object> getObjects() {
        return objects;
    }

    public void setObjects(List<Object> objects) {
        this.objects = objects;
    }

    @Override
    public String toString() {
        return "CredentialsInfoAuth{" +
                "mode='" + mode + '\'' +
                ", expression='" + expression + '\'' +
                ", objects=" + objects +
                '}';
    }
}
