package com.example.auth.security;

import com.example.auth.entity.BlacklistedIP;
import com.example.auth.service.BlacklistedIPService;
import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Component
public class BlacklistedIPAddressFilter extends OncePerRequestFilter {

    private RedisTemplate<String, String> redisTemplate;
    private BlacklistedIPService blacklistedIPService;


    @Override
    protected void initFilterBean() throws ServletException {

        // Set the initFilterBeam() method to call the parent class's initFilterBean() method
        super.initFilterBean();

        // Get the WebApplicationContext from the ServletContext
        WebApplicationContext webApplicationContext =
                WebApplicationContextUtils.getWebApplicationContext(getServletContext());
        assert webApplicationContext != null;

        // Get the RedisTemplate and BlacklistedIPService beans from the WebApplicationContext
        // This needs to be done as traditional dependency injection does not work for Filters
        redisTemplate = webApplicationContext.getBean("redisTemplate", RedisTemplate.class);
        blacklistedIPService = webApplicationContext.getBean("blacklistedIPService", BlacklistedIPService.class);

    }


    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        // Check if the IP address is blacklisted
        Optional<BlacklistedIP> blacklistedIP = blacklistedIPService.findByIpAddress(request.getRemoteAddr());

        if (blacklistedIP.isPresent()) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Your IP address is blacklisted.");
            return;
        }

        // Save and log IP to Redis
        saveIpAddressToRedis(request.getRemoteAddr());

        StringBuilder requestLog = new StringBuilder("\n------------------------------------------------------------\n");

        // Log IP Addresses
        requestLog.append("Local Address: ").append(request.getLocalAddr()).append("\n");
        requestLog.append("Remote Address: ").append(request.getRemoteAddr()).append("\n");

        // HTTP Method
        requestLog.append("HTTP Method: ").append(request.getMethod()).append("\n");

        // Protocol
        requestLog.append("Protocol: ").append(request.getProtocol()).append("\n");

        // Request Details
        requestLog.append("Context Path: ").append(request.getContextPath()).append("\n");
        requestLog.append("Request URI: ").append(request.getRequestURI()).append("\n");

        // Request Parameters
        Map<String, String[]> paramMap = request.getParameterMap();
        for (Map.Entry<String, String[]> entry : paramMap.entrySet()) {
            String paramName = entry.getKey();
            String[] paramValues = entry.getValue();
            requestLog.append("Param ").append(paramName).append(": ");
            requestLog.append(Arrays.toString(paramValues)).append("\n");
        }

        // Log Headers
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            requestLog.append(headerName).append(": ").append(headerValue).append("\n");
        }

        // Cookies
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                requestLog.append("Cookie ").append(cookie.getName()).append(": ");
                requestLog.append(cookie.getValue()).append("\n");
            }
        }

        // Attributes
        Enumeration<String> attributeNames = request.getAttributeNames();
        while (attributeNames.hasMoreElements()) {
            String attributeName = attributeNames.nextElement();
            Object attributeValue = request.getAttribute(attributeName);
            requestLog.append("Attribute ").append(attributeName).append(": ");
            requestLog.append(attributeValue).append("\n");
        }

        // Session Information
        HttpSession session = request.getSession(false);
        if (session != null) {
            requestLog.append("Session ID: ").append(session.getId()).append("\n");

            Enumeration<String> sessionAttributeNames = session.getAttributeNames();
            while (sessionAttributeNames.hasMoreElements()) {
                String attributeName = sessionAttributeNames.nextElement();
                Object attributeValue = session.getAttribute(attributeName);
                requestLog.append("Session Attribute ").append(attributeName).append(": ");
                requestLog.append(attributeValue).append("\n");
            }
        }

        requestLog.append("------------------------------------------------------------\n");

        logger.info(requestLog.toString());

        // Proceed with other filters and request handling
        chain.doFilter(request, response);
    }

    private void saveIpAddressToRedis(String ipAddress) {
        if (redisTemplate != null) {
            // Store the IP address in Redis
            redisTemplate.opsForValue().set(ipAddress, "logged", 24, TimeUnit.HOURS);

            // Log that IP is saved in Redis
            logger.info("Saved IP Address " + ipAddress + " to Redis.");
        } else {
            logger.error("Failed to save IP Address to Redis. RedisTemplate is null.");
        }
    }

}
