/*
 Copyright 2025 European Commission

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

package eu.europa.ec.eudi.signer.r3.authorization_server.config;

public enum AuthenticationMethodEnum {
	LOGIN_FORM(1, "login-form"),
	SAME_DEVICE_FLOW(2, "same-device-flow"),
	CROSS_DEVICE_FLOW(3, "cross-device-flow");

	private final int id;
	private final String value;

	AuthenticationMethodEnum(int id, String value) {
		this.id = id;
		this.value = value;
	}

	public int getId() {
		return id;
	}

	public String getValue() {
		return value;
	}
}