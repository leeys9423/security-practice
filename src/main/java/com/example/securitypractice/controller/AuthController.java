package com.example.securitypractice.controller;

import com.example.securitypractice.oauth.entity.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@Slf4j
public class AuthController {

    @GetMapping("/token")
    public ResponseEntity<String> token(@RequestParam String token) {
        // HTML 형태로 토큰 정보를 보여주는 페이지 반환
        String html = String.format("""
                <html>
                <body>
                    <h2>Access Token:</h2>
                    <textarea rows="5" cols="50" readonly>%s</textarea>
                    <p>Refresh Token Saved</p>
                </body>
                </html>
                """, token);

        return ResponseEntity.ok()
                .contentType(MediaType.TEXT_HTML)
                .body(html);
    }

    // 테스트용 보호된 엔드포인트
    @GetMapping("/test")
    public ResponseEntity<String> test(Authentication authentication) {
        UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
        return ResponseEntity.ok("인증된 사용자 이메일: " + userPrincipal.getEmail());
    }
}
