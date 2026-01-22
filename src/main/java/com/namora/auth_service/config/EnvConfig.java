package com.namora.auth_service.config;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.context.annotation.Configuration;

@Configuration
public class EnvConfig {
    static {
        Dotenv dotenv = Dotenv.configure()
                .directory("./")
                .ignoreIfMissing()
                .load();

        dotenv.entries().forEach(entry ->
                System.setProperty(entry.getKey(), entry.getValue())
        );

        System.out.println("✓ Environment variables loaded from .env (static block)");
    }

    public static void printLoadedEnv() {
        System.out.println("✓ Environment variables loaded from .env");
    }
}