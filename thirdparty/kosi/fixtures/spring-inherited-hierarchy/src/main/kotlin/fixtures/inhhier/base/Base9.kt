package fixtures.inhhier.base

import org.springframework.web.bind.annotation.GetMapping

abstract class Base9 { @GetMapping("/b9") fun b9() = "ok" }
abstract class Same { @GetMapping("/same-base") fun s() = "ok" }
