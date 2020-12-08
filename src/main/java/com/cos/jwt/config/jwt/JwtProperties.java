package com.cos.jwt.config.jwt;

public interface JwtProperties {
	String SECRET = "cos";	//우리서버만 알고있는 비밀값
	int EXPIRATION_TIME = (60000*30);//30분		//10일 (1/1000초) //864000000
	String TOKEN_PREFIX = "BEARER ";
	String HEADER_STRING = "Authorization";

}
