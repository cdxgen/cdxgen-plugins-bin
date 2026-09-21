// Spring's @Controller lives in the stereotype package (spring-context),
// NOT web.bind.annotation — verified against spring-context 5.3.18's own
// jar by the symbol-kind check, which caught the pack modelling the
// wrong FQN. Declared at the real package path so type identity, not name
// similarity, decides the match.
package org.springframework.stereotype

annotation class Controller
