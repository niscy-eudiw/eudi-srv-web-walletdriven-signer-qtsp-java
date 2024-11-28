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

package eu.europa.ec.eudi.signer.r3.authorization_server.web.controller;

import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.HtmlUtils;

import java.util.Objects;

@Controller
public class PersonalizedErrorController {

	@GetMapping(value="/error-page")
	public String handleError(Model model, HttpSession session){
		String errorMessage = (String) session.getAttribute("errorMessage");
		String errorAdditionalInfo = session.getAttribute("errorMessageAdditionalInfo") != null ? (String) session.getAttribute("errorMessageAdditionalInfo") : "";

		session.removeAttribute("errorMessage");
		session.removeAttribute("errorMessageAdditionalInfo");

		if (errorMessage == null)
			errorMessage = "An unexpected error occurred. Please try again later.";
		String safeMessage = HtmlUtils.htmlEscape(errorMessage);
		model.addAttribute("errormessage", safeMessage);

		if(!Objects.equals(errorAdditionalInfo, "")){
			String safeAdditionalInfo = HtmlUtils.htmlEscape(errorAdditionalInfo);
			model.addAttribute("erroradditionalinfo", safeAdditionalInfo);
		}
		return "error";
	}
}
