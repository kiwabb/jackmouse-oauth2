package com.jackmouse.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @ClassName WebSecurityConfig
 * @Description WebSecurityConfig
 * @Author zhoujiaangyao
 * @Date 2022/7/26 22:06
 * @Version 1.0
 **/
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 配置登录系统的用户信息（内存实现）
     * @return 用户信息
     */
    @Bean
    @Override
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withDefaultPasswordEncoder()
                        .username("jackmouse")
                        .password("123456")
                        .roles("USER")
                        .build());
    }

    /**
     * 配置http请求访问权限
     * @param http http
     * @throws Exception Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                //基于jws的认证，放行请求jws数据的请求
                .mvcMatchers("/.well-known/jwks.json").permitAll()
                //任何请求都需要认证
                .anyRequest().authenticated()
                .and()
                //开启httpBasic认证方式
                .httpBasic()
                .and()
                //关闭csrf
                .csrf()
//                .ignoringRequestMatchers((request) -> "/introspect".equals(request.getRequestURI()))
                .disable();
    }

}
