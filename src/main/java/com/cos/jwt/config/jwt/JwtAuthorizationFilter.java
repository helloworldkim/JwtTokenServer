package com.cos.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

//시큐리티가 filter가지고 있는데 그 필터중에 BasicAuthenticationFilter라는것이 있음.
//권한이나 인증이 필요한 특정 주소를 요청했을때 위 필터를 타게되어있음.
//만약에 권한이나 인증이 필요없으면 해당필터를 안탐!
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager,UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
 @Override
protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws IOException, ServletException {
	System.out.println("인증이나 권한이 필요한 주소요청 됨");
	System.out.println(request);
	String jwtHeader = request.getHeader("Authorization");
	System.out.println("jwtHeader :"+jwtHeader);
	
	//header가 있는지 확인
	if(jwtHeader ==null || !jwtHeader.startsWith("Bearer")) {
		chain.doFilter(request, response);
		return;
	}
	
	String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
	
	String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();
	
	if(username != null) {
		User userEntity = userRepository.findByUsername(username);
		
		//jwt토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
		PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
		Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails,null,principalDetails.getAuthorities()); 
		
		//강제로 시큐리티 세션에 접근하여 Authentication객체를 저장
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		chain.doFilter(request, response);
	}
}

}
