package codeyasam.baseclient.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import javax.servlet.http.Cookie;

import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMethod;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;

@Component
public class CustomPostZuulFilter extends ZuulFilter {

	private Logger logger = LoggerFactory.getLogger(this.getClass());
	private ObjectMapper objectMapper = new ObjectMapper();
	
	@Override
	public Object run() {
		RequestContext ctx = RequestContext.getCurrentContext();
		String requestURI = ctx.getRequest().getRequestURI();
		String requestMethod = ctx.getRequest().getMethod();
		logger.info("on Post Zuul Filter");
		logger.info("request URI: " + requestURI);
		logger.info("request method: " + requestMethod);
		
		try {
			final InputStream is = ctx.getResponseDataStream();
			String responseBody = IOUtils.toString(is, "UTF-8");
			if (responseBody.contains("refresh_token")) {
				final Map<Object, String> responseMap = objectMapper.readValue(responseBody, new TypeReference<Map<String, Object>>() {});
				String refreshToken = responseMap.get("refresh_token").toString();
				responseMap.remove("refresh_token");
				responseBody = objectMapper.writeValueAsString(responseMap);
				
				final Cookie cookie = new Cookie("refreshToken", refreshToken);
				cookie.setHttpOnly(true);
				cookie.setPath(ctx.getRequest().getContextPath() + "/oauth/token");
				cookie.setMaxAge(60 * 60 * 24 * 365 * 10);
				ctx.getResponse().addCookie(cookie);
				logger.info("refresh token: " + refreshToken);
				
			} else if (requestURI.contains("oauth/token") && requestMethod.equals(RequestMethod.DELETE)) {
				Cookie cookie = new Cookie("refreshToken", "");
				cookie.setMaxAge(0);
				cookie.setPath(ctx.getRequest().getContextPath() + "/oauth/token");
				ctx.getResponse().addCookie(cookie);
			}
			ctx.setResponseBody(responseBody);
		} catch (IOException e) {
			logger.error("Error occured in zuul filter", e);
		}
		
		return null;
	}

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public int filterOrder() {
		return 10;
	}

	@Override
	public String filterType() {
		return "post";
	}

}
