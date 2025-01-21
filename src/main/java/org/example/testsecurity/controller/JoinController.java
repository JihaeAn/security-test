package org.example.testsecurity.controller;

import org.example.testsecurity.dto.JoinDTO;
import org.example.testsecurity.service.JoinService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
public class JoinController {

	@Autowired
	private JoinService joinService;

	@GetMapping("/join")
	public String joinP() {
		return "join";
	}

	@PostMapping("/joinProc")
	public String joinProc(JoinDTO joinDTO) {

		System.out.println("joinDTO = " + joinDTO);

		joinService.joinProcess(joinDTO);
		return "redirect:/login";
	}
}
