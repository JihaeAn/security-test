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

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                // HTTP 요청에 대한 접근 권한을 설정 (람다식으로 진행)
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/", "/login").permitAll() // permitAll: 모두 허용
                        .requestMatchers("/admin").hasRole("ADMIN")  // hasRole: 해당 롤 가진 사람만 허용
                        .requestMatchers("/my/**").hasAnyRole("ADMIN", "USER") // hasAnyRole: 롤 여러개 정의
                        .anyRequest().authenticated()
                );

        http
                .formLogin((auth) -> auth.loginPage("/login")
                .loginProcessingUrl("/loginProc")
                .permitAll()
                );

        http
                .csrf((auth) -> auth.disable());

        return http.build();
    }

}
