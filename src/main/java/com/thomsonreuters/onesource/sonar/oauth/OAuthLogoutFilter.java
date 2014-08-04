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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.sonar.api.web.ServletFilter;
import org.sonar.plugins.github.oauth.api.GitHubOAuthClient;

/**
 * @author U0165230
 * @since 1.0
 */
public class OAuthLogoutFilter extends ServletFilter {

    private final GitHubOAuthClient oauthClient;

    public OAuthLogoutFilter(GitHubOAuthClient oauthClient) {
        this.oauthClient = oauthClient;
    }

    @Override
    public UrlPattern doGetPattern() {
        return UrlPattern.create("/sessions/logout");
    }

    @Override
    public void init(FilterConfig fc) throws ServletException {
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpSession session = ((HttpServletRequest) servletRequest).getSession(false);
        if (session != null) {
            session.invalidate();
        }
        ((HttpServletResponse) servletResponse).sendRedirect(oauthClient.getSonarServerUrl());
    }

    @Override
    public void destroy() {
    }
}
