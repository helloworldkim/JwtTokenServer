package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		// 토큰 cos 이걸 만들어줘야함 id,pw가 정상적으로 들어와서 로그인이 완료되면 해당 토큰을만들어서 응답해준다
		//요청할때마다 Authorization에 가지고오는 토큰이 만들어준게 맞는지 검증만 하면됨(rsa,hs256)
		
		//토큰  코스!
		if(req.getMethod().equals("POST")) {
			String headerAuth = req.getHeader("Authorization");
			System.out.println(headerAuth);
			
			if(headerAuth.equals("cos")) {
				chain.doFilter(request, response);
			}else {
				PrintWriter out = res.getWriter();
				out.print("인증안됨");
			}
		}

	}

}
