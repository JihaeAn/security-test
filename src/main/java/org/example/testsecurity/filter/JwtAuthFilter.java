package org.example.testsecurity.filter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

import org.example.testsecurity.provider.JwtTokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import kr.co.foryousoft.new4ubackend.config.security.provider.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

	private final JwtTokenProvider jwtTokenProvider;

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		String[] excludeUrl =
			{"/api/admin/auth/sign-in",
			};
		String requestUrl = request.getRequestURI();
		return Arrays.stream(excludeUrl).anyMatch(requestUrl::startsWith);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
		FilterChain filterChain) throws ServletException, IOException {

		// 헤더에서 토큰 가져오기
		String accessTokenFromHeader = jwtTokenProvider.resolveToken(request);
		Authentication authentication;

		try {
			// 토큰 유효성 검사
			if (accessTokenFromHeader != null && jwtTokenProvider.validateToken(accessTokenFromHeader)) {
				try {
					authentication = jwtTokenProvider.getAuthentication(accessTokenFromHeader);
					SecurityContextHolder.getContext().setAuthentication(authentication);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		} catch (ExpiredJwtException e) {
			e.printStackTrace();
			String[] parts = accessTokenFromHeader.split("\\.");
			String payload = new String(Base64.getUrlDecoder().decode(parts[1]));
			ObjectMapper mapper = new ObjectMapper();

			JsonNode jsonNode = mapper.readTree(payload);
			String id = jsonNode.get("sub").asText();
			String refreshToken = String.valueOf(jwtTokenProvider.getTokenFromRedis(id));

			try {
				String newToken = jwtTokenProvider.recreateAccessToken(refreshToken, id);
				response.setHeader("Authorization", "Bearer " + newToken);
				log.info("액세스 토큰이 재발급되었습니다.");
			} catch (Exception e1) {
				e1.printStackTrace();
			}

		}
		filterChain.doFilter(request, response);
	}
}
