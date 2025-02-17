package com.example.securitypractice.oauth.handler;

import com.example.securitypractice.jwt.JwtTokenProvider;
import com.example.securitypractice.oauth.entity.UserPrincipal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Duration;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtTokenProvider tokenProvider;
    private final RedisTemplate<String, String> redisTemplate;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        log.info("OAuth2 Login 성공!");
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();

        // JWT 토큰 생성
        String accessToken = tokenProvider.createAccessToken(userPrincipal.getEmail(), userPrincipal.getRole());
        String refreshToken = tokenProvider.createRefreshToken(userPrincipal.getEmail());

        // Access Token을 Authorization 헤더에 추가
        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken);

        // Refresh Token을 Redis에 저장 (JWT Token Provider에서 이미 처리됨)

        // Refresh Token을 쿠키에 저장
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refresh_token", refreshToken)
                .httpOnly(true)    // JavaScript에서 쿠키에 접근할 수 없도록 설정
//                .secure(true)      // HTTPS에서만 쿠키가 전송되도록 설정
                .secure(false)     // 개발 환경에서는 HTTP도 허용
                .sameSite("Lax")   // CSRF 공격 방지를 위한 설정
                .path("/")         // 쿠키가 유효한 경로 설정 ('/'는 모든 경로에서 사용 가능)
                .maxAge(Duration.ofDays(14))  // 쿠키의 유효기간 설정 (14일)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        // 프론트엔드로 리다이렉트 (Access Token은 쿼리 파라미터로 전달)
//        getRedirectStrategy().sendRedirect(request, response,
//                "/oauth2/redirect?token=" + accessToken);

        // 토큰 확인을 위한 임시 페이지로 리다이렉트
        getRedirectStrategy().sendRedirect(request, response,
                "/auth/token?token=" + accessToken);
    }
}
