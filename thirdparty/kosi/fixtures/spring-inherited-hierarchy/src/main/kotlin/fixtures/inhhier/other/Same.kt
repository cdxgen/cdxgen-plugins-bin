package fixtures.inhhier.other

import org.springframework.web.bind.annotation.GetMapping

abstract class Same { @GetMapping("/same-other") fun s() = "ok" }
