package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig  {
	
	//시큐리티에 등로할 크로스오리진 필터
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true);	//서버가 응답할때 json을 자바스크립트에서 사용하게할지 설정하는부분
		config.addAllowedOrigin("*");		//모든 ip에 응답을 허용
		config.addAllowedHeader("*");	//모든 header에 응답허용
		config.addAllowedMethod("*");	// 모든 요청방법 post get put delete patch 등등
		//해당주소로 접근하면 모든 크로스 오리진을 허락하는 설정적용
		source.registerCorsConfiguration("/api/**", config);
	
		return new CorsFilter(source);
	}
}
