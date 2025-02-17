package com.example.securitypractice.oauth.userinfo;

import java.util.Map;

public class GoogleOAuth2UserInfo extends OAuth2UserInfo {

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getProvider() {
        return "google";
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");  // Google의 경우 'sub'가 사용자 ID
    }
}
