/*
 * Copyright 2020-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package eu.europa.ec.eudi.signer.r3.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.Enumeration;

@RestController
public class DefaultController {

	@GetMapping("/")
	public void root() {
		System.out.println("first call");
		WebClient webClient = WebClient.builder()
				.baseUrl("http://localhost:9000")
				.build();

		webClient.get()
				.uri("/oauth2/authorize?response_type=code&client_id=sca-client&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Flogin%2Foauth2%2Fcode%2Fsca-client-oidc&scope=service&code_challenge=some_nonce&code_challenge_method=S256&lang=pt-PT&state=12345678")
				.retrieve();

		System.out.println("end first call");
	}

	@GetMapping("/login/oauth2/code/sca-client-oidc")
	public void callback(HttpServletRequest request) {
		System.out.println("second call");
		if(request.getParameter("code")== null){
			System.out.println("error: no code");
			return;
		}
		String code = request.getParameter("code");
		System.out.println(code);
		if(request.getParameter("state") == null){
			System.out.println("error: no state");
			return;
		}
		String state = request.getParameter("state");
		System.out.println(state);
		/*WebClient webClient = WebClient.builder()
				.baseUrl("http://localhost:9000")
				.build();

		webClient.post()
				.uri("/oauth2/token?grant_type=code&code="+code+"&client_id=sca-client&client_secret=secret&redirect_uri=http%3A%2F%2Flocalhost%3A8080%2Fauthorized")
				.retrieve();*/

		System.out.println("end second call");
	}

	@GetMapping("/authorized")
	public void final_function(HttpServletRequest request){
		System.out.println("third call");
		Enumeration<String> params = request.getParameterNames();
		while(params.hasMoreElements()){
			System.out.println(params.nextElement());
		}
		System.out.println("end third call");
	}

}
