package com.shopeasy.api.config;

import com.shopeasy.api.security.AuthInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private AuthInterceptor authInterceptor;

    @Value("${app.api.base-path:/api}")
    private String apiBasePath;

    @Value("${app.public-uploads-base-path:/uploads}")
    private String publicUploadsBasePath;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authInterceptor)
                .addPathPatterns(apiBasePath + "/**")
                .excludePathPatterns(
                        apiBasePath + "/auth/signup",
                        apiBasePath + "/auth/login",
                        apiBasePath + "/health",
                        apiBasePath + "/config"
                );
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler(publicUploadsBasePath + "/**")
                .addResourceLocations("file:./uploads/");
    }
}
