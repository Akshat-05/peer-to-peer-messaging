package com.peertopeermessaging.controller;

import com.peertopeermessaging.exception.ApplicationException;
import com.peertopeermessaging.service.UserAuthService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class LoginController {

	@Autowired
	private UserAuthService authService;

	@GetMapping("/login")
	public ResponseEntity<?> login(HttpServletRequest headers) throws ApplicationException {
		String jwt = authService.isValid(headers.getHeader("Authorization"));
		if (jwt == null)
			return ResponseEntity.badRequest().body("Invalid user");
		return ResponseEntity.ok(jwt);
	}
}