/*
 * Onsource Sonar Github oAuth Plugin
 * Copyright (C) 2014 Thomson Reuters
 * john.silva@thomsonreuters.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02
 */
package com.thomsonreuters.onesource.sonar.oauth;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.sonar.api.security.UserDetails;
import org.sonar.api.web.ServletFilter;
import org.sonar.plugins.github.oauth.api.GitHubOAuthClient;

/**
 * @author U0165230
 * @since 1.0
 */
public class OAuthValidationFilter extends ServletFilter {

    private final GitHubOAuthClient oauthClient;

    public OAuthValidationFilter(GitHubOAuthClient oauthClient) {
        this.oauthClient = oauthClient;
    }

    @Override
    public UrlPattern doGetPattern() {
        return UrlPattern.create("/oauth/validate");
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        UserDetails user = oauthClient.validate(servletRequest.getParameterMap());
        HttpServletResponse httpResponse = (HttpServletResponse) servletResponse;

        if (user == null) {
            httpResponse.sendRedirect("/githuboauth/unauthorized");
        } else {
            servletRequest.setAttribute(OAuthUsersProvider.OAUTH_USER_KEY, user);
            filterChain.doFilter(servletRequest, servletResponse);
        }

    }

    @Override
    public void destroy() {
    }
}
