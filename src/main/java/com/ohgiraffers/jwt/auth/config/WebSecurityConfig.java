package com.ohgiraffers.jwt.auth.config;

import com.ohgiraffers.jwt.auth.filter.CustomAuthenticationFilter;
import com.ohgiraffers.jwt.auth.filter.JwtAuthorizationFilter;
import com.ohgiraffers.jwt.auth.handler.CustomAuthFailUserHandler;
import com.ohgiraffers.jwt.auth.handler.CustomAuthSuccessHandler;
import com.ohgiraffers.jwt.auth.handler.CustomAuthenticationProvider;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

    /**
     * 1. 정적 자원에 대한 인증된 사용자의 접근을 설정하는 메서드
     *
     * @return WebSeruciryCusomizer
     * */
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){

        // 특정 요청에 대해 spring security filter chain을 건너뛰도록 하는 역할

        // WebConfig에 설정한 addResourceHandler는 정적 자원에 대해 요청을 할 수 있게 해주는 역할
        // webSecurityCustomizer는 특정 요청에 대해 filterChain을 건너뛰도록 설정하는 역할

        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .addFilterBefore(customAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(jwtAuthorizationFilter(), BasicAuthenticationFilter.class)
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/signup", "/swagger-ui/**", "/v3/api-docs/**", "/swagger-resources/**").permitAll() // Swagger 관련 리소스와 회원가입 경로 허용
                        .requestMatchers("/test").hasRole("ADMIN")
                        .anyRequest()
                        .authenticated() // 나머지 요청은 인증 필요
                );

        return http.build();
    }

    /**
     * 3. Authentization의 인증 메서드를 제공하는 매니저로 Provider의 인터페이스를 의미한다.
     * @return AuthenticationManager
     * */
    @Bean
    public AuthenticationManager authenticationManager(){
        return new ProviderManager(customAuthenticationProvider());
    }

    /**
     * 4. 사용자의 아이디와 패스워드를 DB와 검증하는 handler이다.
     * @return CustomAuthenticationProvider
     * */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }

    /**
     * 비밀번호를 암호화 하는 인코더
     *
     * @return BCryptPasswordEncoder
     * */
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 6. 사용자의 인증 요청을 가로채서 로그인 로직을 수행하는 필터
     * @return CustomAuthenticationFilter
     * */
    @Bean
    public CustomAuthenticationFilter customAuthenticationFilter(){

        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(authenticationManager());

        customAuthenticationFilter.setFilterProcessesUrl("/login");

        customAuthenticationFilter.setAuthenticationSuccessHandler(customAuthLoginSuccessHandler());

        customAuthenticationFilter.setAuthenticationFailureHandler(customAuthFailUserHandler());

        customAuthenticationFilter.afterPropertiesSet();

        return customAuthenticationFilter;
    }

    /**
     * 7. spring security 기반의 사용자의 정보가 맞을 경우 결과를 수행하는 handler
     *
     * @return customAuthLoginSuccessHandler
     * */
    @Bean
    public CustomAuthSuccessHandler customAuthLoginSuccessHandler(){
        return new CustomAuthSuccessHandler();
    }


    /**
     * 8. Spring security의 사용자 정보가 맞지 않은 경우 행되는 메서드
     *
     * @return CustomAuthFailUreHandler
     * */
    @Bean
    public CustomAuthFailUserHandler customAuthFailUserHandler(){
        return new CustomAuthFailUserHandler();
    }

    /**
     * 9. 사용자 요청시 수행되는 메소드
     * @return JwtAuthorizationFilter
     * */
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter(){
        return new JwtAuthorizationFilter(authenticationManager());
    }

}
