package com.jackmouse.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

/**
 * 排除数据源自动配置
 * 开启oauth认证服务器
 * @author zhoujiaangyao
 */

@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
@EnableAuthorizationServer
public class Oauth2AuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2AuthServerApplication.class, args);
    }

}
