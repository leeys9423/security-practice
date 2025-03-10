package com.example.securitypractice.oauth.service;

import com.example.securitypractice.entity.Member;
import com.example.securitypractice.entity.Role;
import com.example.securitypractice.entity.SocialAccount;
import com.example.securitypractice.entity.SocialProvider;
import com.example.securitypractice.oauth.entity.UserPrincipal;
import com.example.securitypractice.oauth.exception.OAuth2AuthenticationProcessingException;
import com.example.securitypractice.oauth.userinfo.OAuth2UserInfo;
import com.example.securitypractice.oauth.userinfo.OAuth2UserInfoFactory;
import com.example.securitypractice.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        try {
            return this.process(userRequest, oauth2User);
        } catch (Exception ex) {
            log.error("OAuth2 인증 처리 중 에러 발생", ex);
            throw new OAuth2AuthenticationProcessingException(ex.getMessage(), ex);
        }
    }

    private OAuth2User process(OAuth2UserRequest userRequest, OAuth2User oauth2User) {
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
                registrationId,
                oauth2User.getAttributes()
        );

        log.info("provider from userInfo: {}", userInfo.getProvider());  // 로그 추가
        log.info("attributes: {}", oauth2User.getAttributes());  // 로그 추가

        String email = userInfo.getEmail();
        if (!StringUtils.hasText(email)) {
            throw new OAuth2AuthenticationProcessingException(
                    "Email not found from OAuth2 provider"
            );
        }

        // 이메일로 기존 회원 찾기
        Optional<Member> memberOptional = memberRepository.findByEmail(email);

        Member member;
        if (memberOptional.isEmpty()) {
            // 새로운 회원 및 소셜 계정 정보 저장
            SocialAccount socialAccount = SocialAccount.builder()
                    .provider(SocialProvider.valueOf(registrationId.toUpperCase()))
                    .socialId(userInfo.getId())
                    .build();

            member = Member.builder()
                    .name("테스트")
                    .password("")
                    .email(email)
                    .role(Role.USER)
                    .build();

            socialAccount.setMember(member);
            member.getSocialAccounts().add(socialAccount);

            member = memberRepository.save(member);
            log.info("새로운 회원가입이 완료되었습니다. email: {}", email);
        } else {
            member = memberOptional.get();

            // 해당 소셜 계정이 이미 있는지 확인
            boolean hasSocialAccount = member.getSocialAccounts().stream()
                    .anyMatch(account ->
                            account.getProvider() == SocialProvider.valueOf(registrationId.toUpperCase()) &&
                                    account.getSocialId().equals(userInfo.getId())
                    );

            // 소셜 계정이 없다면 추가
            if (!hasSocialAccount) {
                SocialAccount socialAccount = SocialAccount.builder()
                        .provider(SocialProvider.valueOf(registrationId.toUpperCase()))
                        .socialId(userInfo.getId())
                        .build();

                socialAccount.setMember(member);
                member.getSocialAccounts().add(socialAccount);

                member = memberRepository.save(member);
                log.info("기존 회원에 새로운 소셜 계정이 추가되었습니다. email: {}, provider: {}", email, registrationId);
            }

            log.info("기존 회원이 로그인했습니다. email: {}", email);
        }

        return UserPrincipal.create(member, oauth2User.getAttributes());
    }

    private Member registerNewMember(OAuth2UserInfo userInfo) {
        Member member = Member.builder()
                .email(userInfo.getEmail())
                .role(Role.USER)
                .build();

        return memberRepository.save(member);
    }
}
