package com.cos.jwt.controller;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class RestApiController {
	
	private final UserRepository userRepository;
	private final BCryptPasswordEncoder passwordEncoder;
	

	@GetMapping("/home")
	public String home() {

		return "<h1>홈</h1>";
	}
	
	@PostMapping("/token")
	public String token() {
		
		return "<h1>token</h1>";
	}
	
	@PostMapping("/join")
	public String join(@RequestBody User user) {
		System.out.println("정보받냐?!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
		System.out.println(user.getUsername());
		System.out.println(user.getPassword());
		user.setPassword(passwordEncoder.encode(user.getPassword()));
		user.setRoles("ROLE_USER");
		userRepository.save(user);
		return "회원가입 완료";
	}
}
