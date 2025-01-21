package org.example.testsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// @Bean
	// public RoleHierarchyImpl roleHierarchy() {
	//
	// 	return RoleHierarchyImpl.withDefaultRolePrefix()
	// 		.role("C").implies("B")
	// 		.role("B").implies("A")
	// 		.build();
	// }

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		http
			// HTTP 요청에 대한 접근 권한을 설정 (람다식으로 진행)
			.authorizeHttpRequests((auth) -> auth
				.requestMatchers("/", "/login", "/join", "/joinProc").permitAll() // permitAll: 모두 허용
				.requestMatchers("/admin").hasRole("ADMIN")  // hasRole: 해당 롤 가진 사람만 허용
				.requestMatchers("/my/**").hasAnyRole("ADMIN", "USER") // hasAnyRole: 롤 여러개 정의
				.anyRequest().authenticated()
			);

		http
			.formLogin((auth) -> auth.loginPage("/login")
				.loginProcessingUrl("/loginProc")
				.permitAll()
			);
		// .httpBasic(Customizer.withDefaults());

		http
			.csrf((auth) -> auth.disable());

		http
			.sessionManagement((auth) -> auth
				.maximumSessions(1) // 하나의 아이디에 대한 다중 로그인 허용 개수
				.maxSessionsPreventsLogin(true)); // 다중 로그인 개수를 초과했을 경우 처리 방법 (true: 새로운 로그인 차단, false: 기존 세션 하나 삭제)

		http
			.sessionManagement((auth) -> auth
				.sessionFixation().changeSessionId()); // 로그인 시 동일한 세션에 대한 id 변경

		return http.build();
	}

}
