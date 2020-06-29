package com.smy;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * SpringBoot启动类
 * @author lenovo
 *
 */
@SpringBootApplication
//通过使用@MapperScan可以指定要扫描的Mapper类的包的路径   同时,使用@MapperScan注解多个包
@MapperScan("com.smy.mapper")
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
