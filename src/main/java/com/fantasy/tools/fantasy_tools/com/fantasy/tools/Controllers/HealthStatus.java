package com.fantasy.tools.fantasy_tools.com.fantasy.tools.Controllers;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HealthStatus {

    @RequestMapping("/health-status")
    public String index() {
        return "Healthy!";
    }
}
