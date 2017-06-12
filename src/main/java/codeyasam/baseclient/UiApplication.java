package codeyasam.baseclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.zuul.EnableZuulProxy;

@EnableZuulProxy
@SpringBootApplication
public class UiApplication {
	
	public static void main(String[] args) {
		SpringApplication.run(UiApplication.class, args);
	}
}
