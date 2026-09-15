// alg=none: the mapping row names the family jwt and carries the finding.
// A signed JWT (HS256) is the negative half: it must produce NO asset.
// kosi:want crypto name=none form=literal mode=resolved
// kosi:want-not crypto name=HS256 mode=resolved
package fixtures.cryptotls

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.SignatureAlgorithm

fun unsignedToken(): String =
    Jwts.builder().signWith(SignatureAlgorithm.NONE).compact()
