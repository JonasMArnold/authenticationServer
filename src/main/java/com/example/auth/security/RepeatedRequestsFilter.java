package com.example.auth.security;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

@Component
public class RepeatedRequestsFilter extends OncePerRequestFilter {

    private TimedRepetitionCounter timedRepetitionCounter;


    @Override
    protected void initFilterBean() throws ServletException {
        super.initFilterBean();
        this.timedRepetitionCounter = new TimedRepetitionCounter(Duration.ofSeconds(30), 15);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String srcIp = request.getRemoteAddr();

        if(this.timedRepetitionCounter.count(srcIp)) {
            logger.trace("Checked " + srcIp + " for spammed requests. Not filtering.");
            chain.doFilter(request, response);

        } else {
            logger.info("Filtered " + srcIp + ". Too many requests!");

            //send status code "too many requests"
            response.sendError(429, "Too many requests.");
        }
    }
}

