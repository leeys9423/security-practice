package com.example.securitypractice.config;

import com.example.securitypractice.jwt.JwtAuthenticationFilter;
import com.example.securitypractice.jwt.JwtExceptionFilter;
import com.example.securitypractice.jwt.JwtTokenProvider;
import com.example.securitypractice.oauth.handler.OAuth2AuthenticationFailureHandler;
import com.example.securitypractice.oauth.handler.OAuth2AuthenticationSuccessHandler;
import com.example.securitypractice.oauth.service.CustomOAuth2UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtTokenProvider jwtTokenProvider;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final OAuth2AuthenticationSuccessHandler oAuth2AuthenticationSuccessHandler;
    private final OAuth2AuthenticationFailureHandler oAuth2AuthenticationFailureHandler;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                // CSRF 비활성화
                .csrf(AbstractHttpConfigurer::disable)
                // CORS 설정
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 세션 설정(비활성화)
                .sessionManagement(
                        (sessionManagement) ->
                                sessionManagement.sessionCreationPolicy(
                                        SessionCreationPolicy.STATELESS))
                // 요청에 대한 권한 설정
                .authorizeHttpRequests(
                        (authorizeRequests) ->
                                authorizeRequests
                                        .requestMatchers("/swagger-ui/**")
                                        .permitAll() // Swagger UI 허용
                                        .requestMatchers("/v3/api-docs/**")
                                        .permitAll() // API Docs 허용
                                        .requestMatchers("/oauth2/**", "/auth/**")
                                        .permitAll()
                                        .anyRequest()
                                        .authenticated() // 그 외 요청은 인증 필요
                )
                // OAuth2 로그인 설정
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(customOAuth2UserService))
                        .successHandler(oAuth2AuthenticationSuccessHandler)
                        .failureHandler(oAuth2AuthenticationFailureHandler))
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider),
                        UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtExceptionFilter(),
                        JwtAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // 허용할 Origin 설정
        configuration.setAllowedOrigins(
                List.of(
                        "http://localhost:5173", // 로컬 프론트엔드
                        "http://localhost:8080"
                ));

        // 허용할 HTTP 메서드
        configuration.setAllowedMethods(
                List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));

        // 허용할 헤더
        configuration.setAllowedHeaders(
                List.of("Authorization", "Content-Type", "Cache-Control", "x-requested-with"));

        // 노출할 헤더 설정 추가
        configuration.setExposedHeaders(List.of("Authorization"));

        // 인증 정보 포함 허용
        configuration.setAllowCredentials(true);

        // preflight 요청의 캐시 시간 (1시간)
        // API 요청 시 서버는 OPTIONS 메서드를 통해 제공하는 메서드인지를 먼저 체크한다.
        // 캐싱을 통해 불필요한 preflight 요청을 줄여서 성능을 개선
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}
