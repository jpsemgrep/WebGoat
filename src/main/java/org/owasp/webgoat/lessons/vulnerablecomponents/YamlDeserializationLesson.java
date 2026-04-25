/*
 * SPDX-FileCopyrightText: Copyright © 2026 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.lessons.vulnerablecomponents;

import static org.owasp.webgoat.container.assignments.AttackResultBuilder.failed;
import static org.owasp.webgoat.container.assignments.AttackResultBuilder.success;

import org.owasp.webgoat.container.assignments.AssignmentEndpoint;
import org.owasp.webgoat.container.assignments.AttackResult;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.yaml.snakeyaml.Yaml;

/**
 * SnakeYAML deserialization lesson — exercises CVE-2022-1471 (unsafe SnakeYAML
 * Constructor allowing arbitrary class instantiation from untrusted YAML).
 *
 * <p>Added to seed the plumbline reachability workflow with a transitive-dep
 * vulnerability that has both a callable sink ({@code Yaml.load}) and a
 * Semgrep-emitted {@code reachableCondition}. SnakeYAML is brought in
 * transitively via {@code spring-boot-starter}; this codebase pins it to 1.33
 * via the {@code <snakeyaml.version>} property in {@code pom.xml}.
 */
@RestController
public class YamlDeserializationLesson implements AssignmentEndpoint {

  @PostMapping("/VulnerableComponents/yaml")
  public @ResponseBody AttackResult parseYaml(@RequestParam String payload) {
    try {
      Yaml yaml = new Yaml();
      Object parsed = yaml.load(payload);
      if (parsed != null) {
        return success(this).output(parsed.toString()).build();
      }
      return failed(this).output("empty").build();
    } catch (Exception ex) {
      return failed(this).output(ex.getMessage()).build();
    }
  }
}
