package com.jackmouse.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;

/**
 * @ClassName AuthorizationServerConfig
 * @Description
 * @Author zhoujiaangyao
 * @Date 2022/7/26 22:16
 * @Version 1.0
 **/
@Configuration
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {
    /**
     * 密码加密
     * @return PasswordEncoder
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /**
     * 配置客户端信息（内存实现）
     * @param clients 客户端
     * @throws Exception Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                //客户端名称
                .withClient("first-client")
                //客户端密码
                .secret(passwordEncoder().encode("noonewilleverguess"))
                //权限
                .scopes("resource:read")
                //支持认证的方式
                .authorizedGrantTypes("authorization_code", "password")
                //重定向url
                .redirectUris("http://localhost:8080/login/oauth2/code/goodskill",
                        "http://www.goodskill.com:8080/login/oauth2/code/goodskill")
                .and()
                .withClient("second-client")
                .secret(passwordEncoder().encode("noonewilleverguess"))
                .scopes("resource:read")
                .authorizedGrantTypes("authorization_code", "password")
                .redirectUris(
                        "http://www.goodskill.com:8080/login/oauth2/code/goodskill",
                        "http://localhost:19021/login/oauth2/code/goodskill"
                )
        ;
    }

}
