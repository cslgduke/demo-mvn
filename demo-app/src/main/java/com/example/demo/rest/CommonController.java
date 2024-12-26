package com.example.demo.rest;

import lombok.extern.slf4j.Slf4j;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

/**
 * @author i565244
 */
@RequestMapping(value = {"/common"})
@Validated
@RestController
@Slf4j
public class CommonController {


    @RequestMapping("/uuid")
    public String generateUUid() {
        var uuid = UUID.randomUUID();
        return String.valueOf(uuid);
    }

    @PostMapping("/uuid")
    public String generateUUid_post() {
        var uuid = UUID.randomUUID();
        return String.valueOf(uuid);
    }

}
